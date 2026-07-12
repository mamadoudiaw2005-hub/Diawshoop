/**
 * DIAW SHOOP - Core Application Script
 * Features: Authentication (Classic & Google), Responsive Cart, Sizing Guide,
 * WhatsApp Direct Order, Secure Role-based Admin Dashboard (CRUD & Orders),
 * and Multi-channel Senegalese Mobile Payment Simulation (Wave, OM, Free).
 */

// --- 1. CONFIGURATION & DEFAULT DATA SEEDING ---
const SELLER_WHATSAPP = "221785946427"; // Phone number for Senegalese WhatsApp ordering

// Default beauty and women's fashion collections
const DEFAULT_PRODUCTS = [
    {
        id: "prod-001",
        name: "Abaya en Soie Premium Oud",
        category: "vetements",
        price: 24500,
        description: "Robe abaya longue premium en soie de Médine fluide. Coupe évasée élégante idéale pour les occasions spéciales ou le quotidien. Matière respirante et opaque, adaptée pour les femmes voilées.",
        image: "assets/abaya_silk.webp",
        videoUrl: "https://assets.mixkit.co/videos/preview/mixkit-woman-modeling-a-silk-green-dress-40995-large.mp4",
        stocks: { S: 8, M: 12, L: 10, XL: 4 }
    },
    {
        id: "prod-002",
        name: "Robe Wax Moderne Dakar Gold",
        category: "robes",
        price: 18500,
        description: "Superbe robe wax évasée avec broderies et détails en fil doré. Fabriquée à la main à Dakar avec un tissu wax de qualité supérieure, combinant tradition et modernité chic.",
        image: "assets/dress_wax.webp",
        stocks: { S: 10, M: 15, L: 8, XL: 5 }
    },
    {
        id: "prod-003",
        name: "Crème Karité Fondante Bio",
        category: "beaute",
        price: 8500,
        description: "Soin corporel hydratant intense formulé à base de beurre de karité pur du Sénégal. Enrichi en huiles de coco et d'avocat pour nourrir et réparer en profondeur les peaux sèches.",
        image: "assets/shea_cream.webp",
        stocks: { S: 99, M: 99, L: 99, XL: 99 }
    },
    {
        id: "prod-004",
        name: "Sérum Éclat aux Huiles Précieuses",
        category: "beaute",
        price: 14500,
        description: "Élixir régénérant visage aux huiles d'hibiscus et de baobab bio. Unifie le teint, lutte contre les imperfections et redonne un éclat naturel à votre peau.",
        image: "assets/serum_glow.webp",
        stocks: { S: 99, M: 99, L: 99, XL: 99 }
    },
    {
        id: "prod-005",
        name: "Encens Thiouraye Royal & Brume Oud",
        category: "parfums",
        price: 12500,
        description: "Coffret senteurs sénégalaises comprenant un pot de thiouraye d'encens traditionnel parfumé et une brume de corps au bois de oud oriental pour une tenue longue durée.",
        image: "assets/perfume_oud.webp",
        stocks: { S: 99, M: 99, L: 99, XL: 99 }
    }
];

// Helper to escape HTML and prevent XSS (Cross-Site Scripting)
function escapeHTML(str) {
    if (!str) return '';
    return str.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Cryptographic SHA-256 Implementation for password hashing
function sha256(ascii) {
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }
    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var lengthProperty = 'length';
    var i, j;
    var result = '';
    var words = [];
    var asciiLength = ascii[lengthProperty] * 8;
    var hash = sha256.h = sha256.h || [];
    var k = sha256.k = sha256.k || [];
    var primeCounter = k[lengthProperty];
    var isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
            for (i = 0; i < 313; i += candidate) {
                isComposite[i] = candidate;
            }
            hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
            k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
        }
    }
    ascii += '\x80';
    while (ascii[lengthProperty] % 64 - 56) ascii += '\x00';
    for (i = 0; i < ascii[lengthProperty]; i++) {
        j = ascii.charCodeAt(i);
        if (j >> 8) return; // Only support ASCII
        words[i >> 2] |= j << (24 - (i % 4) * 8);
    }
    words[words[lengthProperty]] = ((asciiLength / maxWord) | 0);
    words[words[lengthProperty]] = (asciiLength);
    for (j = 0; j < words[lengthProperty];) {
        var w = words.slice(j, j += 16);
        var oldHash = hash.slice(0);
        for (i = 0; i < 64; i++) {
            var w16 = w[i - 16], w15 = w[i - 15], w7 = w[i - 7], w2 = w[i - 2];
            var a = hash[0], e = hash[4], temp1, temp2;
            w[i] = i < 16 ? w[i] : (
                w[i - 16] +
                (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
                w7 +
                (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
            ) | 0;
            temp1 = (hash[7] +
                (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
                ((e & hash[5]) ^ (~e & hash[6])) +
                k[i] +
                w[i]) | 0;
            temp2 = ((rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
                ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]))) | 0;
            hash = [(temp1 + temp2) | 0].concat(hash);
            hash[4] = (hash[4] + temp1) | 0;
            hash.length = 8;
        }
        for (i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i]) | 0;
        }
    }
    for (i = 0; i < 8; i++) {
        for (j = 31; j >= 0; j -= 4) {
            var digit = (hash[i] >> j) & 0xf;
            result += digit.toString(16);
        }
    }
    return result;
}

function mockHashPassword(password) {
    return sha256(password);
}

// Initialize LocalStorage Data
function initializeStorage() {
    // Force reset products if the catalog needs update (e.g. videoUrl seed)
    if (localStorage.getItem("diaw_shoop_products")) {
        const prodCheck = JSON.parse(localStorage.getItem("diaw_shoop_products")) || [];
        if (prodCheck.some(p => p.id === "prod-001" && !p.videoUrl)) {
            localStorage.removeItem("diaw_shoop_products");
        }
    }
    // 1. Seed Products if not present
    if (!localStorage.getItem("diaw_shoop_products")) {
        localStorage.setItem("diaw_shoop_products", JSON.stringify(DEFAULT_PRODUCTS));
    }
    
    // 2. Seed default users (Admin & Client)
    if (localStorage.getItem("diaw_shoop_users")) {
        const usersCheck = JSON.parse(localStorage.getItem("diaw_shoop_users")) || [];
        const mamadou = usersCheck.find(u => u.email === "mamadoudiaw2005@gmail.com");
        // Force reset users database if using older reversed-string hash format or missing permissions
        if (!mamadou || !mamadou.permissions || !mamadou.permissions.canAddEdit || !mamadou.passwordHash || mamadou.passwordHash.length !== 64) {
            localStorage.removeItem("diaw_shoop_users");
        }
    }
    if (!localStorage.getItem("diaw_shoop_users")) {
        const defaultUsers = [
            {
                email: "mamadoudiaw2005@gmail.com",
                passwordHash: mockHashPassword("DIAW2005"),
                name: "Mamadou Diaw (Grand Admin)",
                isAdmin: true,
                isSuperAdmin: true,
                avatar: "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&q=80&w=100&h=100"
            },
            {
                email: "diarra.diaw@diawshoop.sn",
                passwordHash: mockHashPassword("diarra123"),
                name: "Diarra Diaw (Admin)",
                isAdmin: true,
                isSuperAdmin: false,
                permissions: { canAddEdit: true, canDelete: false, canManageOrders: true },
                avatar: "https://images.unsplash.com/photo-1580489944761-15a19d654956?auto=format&fit=crop&q=80&w=100&h=100"
            },
            {
                email: "client@gmail.com",
                passwordHash: mockHashPassword("client123"),
                name: "Awa Ndiaye",
                isAdmin: false,
                isSuperAdmin: false,
                avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=100&h=100"
            }
        ];
        localStorage.setItem("diaw_shoop_users", JSON.stringify(defaultUsers));
    }

    // 3. Seed orders list if empty
    if (!localStorage.getItem("diaw_shoop_orders")) {
        localStorage.setItem("diaw_shoop_orders", JSON.stringify([]));
    }

    // Seed default reviews list if empty
    if (!localStorage.getItem("diaw_shoop_reviews")) {
        const defaultReviews = [
            {
                id: "rev-001",
                productId: "prod-001",
                author: "Sokhna Diop",
                rating: 5,
                text: "Abaya magnifique, la soie est d'une légèreté et d'une qualité exceptionnelle ! Je recommande vivement.",
                date: "2026-07-10T14:32:00.000Z",
                avatar: "https://api.dicebear.com/7.x/initials/svg?seed=Sokhna%20Diop"
            },
            {
                id: "rev-002",
                productId: "prod-001",
                author: "Fatou Diene",
                rating: 4,
                text: "Très satisfaite de mon achat, la coupe est parfaite. Seul bémol : la livraison a pris 24h de plus que prévu.",
                date: "2026-07-09T10:15:00.000Z",
                avatar: "https://api.dicebear.com/7.x/initials/svg?seed=Fatou%20Diene"
            },
            {
                id: "rev-003",
                productId: "prod-002",
                author: "Aminata Ndoye",
                rating: 5,
                text: "Le motif wax est sublime et les couleurs éclatantes. Parfait pour les grandes occasions !",
                date: "2026-07-11T09:45:00.000Z",
                avatar: "https://api.dicebear.com/7.x/initials/svg?seed=Aminata%20Ndoye"
            },
            {
                id: "rev-004",
                productId: "prod-003",
                author: "Mariama Sy",
                rating: 5,
                text: "Excellent produit pour hydrater la peau en profondeur. Texture très agréable et odeur naturelle discrète.",
                date: "2026-07-08T16:20:00.000Z",
                avatar: "https://api.dicebear.com/7.x/initials/svg?seed=Mariama%20Sy"
            }
        ];
        localStorage.setItem("diaw_shoop_reviews", JSON.stringify(defaultReviews));
    }

    // 4. Seed default shop settings if not present
    if (localStorage.getItem("diaw_shoop_settings")) {
        const settingsCheck = JSON.parse(localStorage.getItem("diaw_shoop_settings")) || {};
        if (!settingsCheck.instagram || !settingsCheck.googleClientId || !settingsCheck.shopName) {
            localStorage.removeItem("diaw_shoop_settings");
        }
    }
    if (!localStorage.getItem("diaw_shoop_settings")) {
        const defaultSettings = {
            whatsapp: "221785946427",
            email: "mamadoudiaw2005@gmail.com",
            address: "Liberté 6 Extension, Dakar, Sénégal",
            hours: "Lun - Ven : 10h - 22h / Sam : 10h - 18h",
            instagram: "https://instagram.com/",
            facebook: "https://facebook.com/",
            tiktok: "https://tiktok.com/",
            googleClientId: "845239922097-n8l4g8i4e2j99p0lhq1f3c30r7o0p61i.apps.googleusercontent.com"
        };
        localStorage.setItem("diaw_shoop_settings", JSON.stringify(defaultSettings));
    }
}

initializeStorage();
applyStoreSettings();

// --- 2. GLOBAL STATE ---
let products = JSON.parse(localStorage.getItem("diaw_shoop_products"));
let orders = JSON.parse(localStorage.getItem("diaw_shoop_orders"));
let currentUser = JSON.parse(sessionStorage.getItem("diaw_shoop_current_user")) || null;
let cart = JSON.parse(localStorage.getItem("diaw_shoop_cart")) || [];
let reviews = JSON.parse(localStorage.getItem("diaw_shoop_reviews")) || [];

// Active shop filter state
let activeCategory = "all";
let searchFilter = "";
let sortOrder = "default";

// Checkout wizard temporary state
let checkoutDetails = {
    name: "",
    phone: "",
    email: "",
    address: "",
    notes: "",
    deliveryZone: "dakar-centre",
    shippingCost: 1500,
    paymentMethod: "",
    items: [],
    subtotal: 0,
    total: 0
};

// Target edit product (for admin)
let editingProductId = null;
let customImageBase64 = "";
let customVideoBase64 = "";

// --- 3. DOM ELEMENTS ---
const elements = {
    // Header & Navigation
    loginTriggerBtn: document.getElementById("login-trigger-btn"),
    userDropdownContainer: document.getElementById("user-dropdown-container"),
    userProfileBtn: document.getElementById("user-profile-btn"),
    userAvatar: document.getElementById("user-avatar"),
    userNameDisplay: document.getElementById("user-name-display"),
    userEmailDisplay: document.getElementById("user-email-display"),
    userRoleBadge: document.getElementById("user-role-badge"),
    btnLogout: document.getElementById("btn-logout"),
    navAdmin: document.getElementById("nav-admin"),
    dropdownAdminBtn: document.getElementById("dropdown-admin-btn"),
    navHome: document.getElementById("nav-home"),
    navShop: document.getElementById("nav-shop"),
    
    // Product Catalogue Grid & Filters
    productsGrid: document.getElementById("products-grid"),
    categoryTabs: document.getElementById("category-tabs"),
    searchInput: document.getElementById("search-input"),
    searchBtn: document.getElementById("search-btn"),
    sortSelect: document.getElementById("sort-select"),
    activeFiltersInfo: document.getElementById("active-filters-info"),
    searchQueryText: document.getElementById("search-query-text"),
    clearSearchBtn: document.getElementById("clear-search-btn"),
    
    // Cart Sidebar Drawer
    cartSidebar: document.getElementById("cart-sidebar"),
    cartTriggerBtn: document.getElementById("cart-trigger-btn"),
    closeCartBtn: document.getElementById("close-cart-btn"),
    sidebarOverlay: document.getElementById("sidebar-overlay"),
    cartSidebarBody: document.getElementById("cart-sidebar-body"),
    cartSidebarFooter: document.getElementById("cart-sidebar-footer"),
    cartBadge: document.getElementById("cart-badge"),
    cartSubtotal: document.getElementById("cart-subtotal"),
    cartShippingCost: document.getElementById("cart-shipping-cost"),
    cartTotal: document.getElementById("cart-total"),
    cartDeliveryZone: document.getElementById("cart-delivery-zone"),
    btnCheckoutTrigger: document.getElementById("btn-checkout-trigger"),
    btnCartContinue: document.getElementById("btn-cart-continue"),
    
    // Auth Modal
    authModal: document.getElementById("auth-modal"),
    btnCloseAuthModal: document.getElementById("btn-close-auth-modal"),
    authTabs: document.querySelectorAll(".auth-tab-btn"),
    loginForm: document.getElementById("login-form"),
    registerForm: document.getElementById("register-form"),
    btnGoogleLogin: document.getElementById("btn-google-login"),
    
    // Google OAuth Popup Dialog
    googlePopupOverlay: document.getElementById("google-popup-overlay"),
    btnCloseGooglePopup: document.getElementById("btn-close-google-popup"),
    googleAccountItems: document.querySelectorAll(".google-account-item"),
    
    // Product Detail Modal
    productDetailModal: document.getElementById("product-detail-modal"),
    btnCloseProductModal: document.getElementById("btn-close-product-modal"),
    modalProductImage: document.getElementById("modal-product-image"),
    modalProductCategory: document.getElementById("modal-product-category"),
    modalProductTitle: document.getElementById("modal-product-title"),
    modalProductPrice: document.getElementById("modal-product-price"),
    modalProductDesc: document.getElementById("modal-product-desc"),
    sizeOptionsContainer: document.getElementById("size-options-container"),
    modalStockStatus: document.getElementById("modal-stock-status"),
    modalBtnAddCart: document.getElementById("modal-btn-add-cart"),
    modalBtnWhatsapp: document.getElementById("modal-btn-whatsapp"),
    
    // User Orders Modal
    myOrdersModal: document.getElementById("my-orders-modal"),
    btnCloseMyOrders: document.getElementById("btn-close-my-orders"),
    btnCloseMyOrdersBtn: document.getElementById("btn-close-my-orders-btn"),
    btnMyOrders: document.getElementById("btn-my-orders"),
    myOrdersList: document.getElementById("my-orders-list"),
    
    // Checkout Modal & Senegalese Mobile Payment Wizards
    checkoutModal: document.getElementById("checkout-modal"),
    btnCloseCheckoutModal: document.getElementById("btn-close-checkout-modal"),
    shippingInfoForm: document.getElementById("shipping-info-form"),
    checkoutAmountSummary: document.getElementById("checkout-amount-summary"),
    btnProceedToSim: document.getElementById("btn-proceed-to-sim"),
    btnBackToStep1: document.getElementById("btn-back-to-step-1"),
    btnBackToStep2: document.getElementById("btn-back-to-step-2"),
    btnCheckoutCloseComplete: document.getElementById("btn-close-checkout-complete"),
    btnDownloadPdf: document.getElementById("btn-download-pdf"),
    invoiceReceiptDetails: document.getElementById("invoice-receipt-details"),
    transactionLoader: document.getElementById("transaction-loader"),
    simNavButtons: document.getElementById("sim-nav-buttons"),
    
    // Admin Section & Forms
    adminSection: document.getElementById("admin-section"),
    btnCloseAdmin: document.getElementById("btn-close-admin"),
    productAdminForm: document.getElementById("product-admin-form"),
    btnSaveProduct: document.getElementById("btn-save-product"),
    btnCancelEdit: document.getElementById("btn-cancel-edit"),
    editProductIdInput: document.getElementById("edit-product-id"),
    prodNameInput: document.getElementById("prod-name"),
    prodPriceInput: document.getElementById("prod-price"),
    prodCategorySelect: document.getElementById("prod-category"),
    prodDescTextarea: document.getElementById("prod-desc"),
    prodImagePresetSelect: document.getElementById("prod-image-preset"),
    prodImageUrlInput: document.getElementById("prod-image-url"),
    prodImageFileInput: document.getElementById("prod-image-file"),
    prodVideoInput: document.getElementById("prod-video"),
    prodVideoFileInput: document.getElementById("prod-video-file"),
    modalMediaContainer: document.getElementById("modal-media-container"),
    adminProductsTableBody: document.getElementById("admin-products-table-body"),
    adminOrdersTableBody: document.getElementById("admin-orders-table-body"),
    adminPendingBadge: document.getElementById("admin-pending-badge"),
    adminStatRevenue: document.getElementById("admin-stat-revenue"),
    adminStatOrders: document.getElementById("admin-stat-orders"),
    adminStatProducts: document.getElementById("admin-stat-products"),
    adminRolesTableBody: document.getElementById("admin-roles-table-body"),
    
    // Toasts Alert Wrapper
    toastContainer: document.getElementById("toast-container")
};

// Add dynamic events for form toggle password
document.querySelectorAll(".btn-toggle-password").forEach(btn => {
    btn.addEventListener("click", function() {
        const input = this.previousElementSibling;
        const icon = this.querySelector("i");
        if (input.type === "password") {
            input.type = "text";
            icon.classList.replace("fa-eye", "fa-eye-slash");
        } else {
            input.type = "password";
            icon.classList.replace("fa-eye-slash", "fa-eye");
        }
    });
});

// --- 4. TOAST NOTIFICATION UTILITY ---
function showToast(message, type = "success") {
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    
    let iconClass = "fa-circle-check";
    if (type === "error") iconClass = "fa-circle-exclamation";
    if (type === "info") iconClass = "fa-circle-info";
    
    toast.innerHTML = `<i class="fa-solid ${iconClass}"></i> <span>${escapeHTML(message)}</span>`;
    elements.toastContainer.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = "toastIn 0.3s reverse forwards";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// --- 5. AUTHENTICATION FLOWS (CLASSIC & SIMULATED GOOGLE OAUTH) ---
function updateUserUI() {
    if (currentUser) {
        // Authenticated State
        elements.loginTriggerBtn.style.display = "none";
        elements.userDropdownContainer.style.display = "block";
        elements.userAvatar.src = currentUser.avatar || "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&q=80&w=100";
        elements.userNameDisplay.textContent = currentUser.name;
        elements.userEmailDisplay.textContent = currentUser.email;
        
        if (currentUser.isAdmin) {
            elements.userRoleBadge.textContent = currentUser.isSuperAdmin ? "Grand Admin" : "Admin Secondaire";
            elements.userRoleBadge.className = "badge badge-accent";
            document.querySelectorAll(".admin-only-link").forEach(el => el.style.display = "block");
            renderAdminDashboard();
        } else {
            elements.userRoleBadge.textContent = "Client";
            elements.userRoleBadge.className = "badge badge-success";
            document.querySelectorAll(".admin-only-link").forEach(el => el.style.display = "none");
            elements.adminSection.style.display = "none";
        }
    } else {
        // Guest State
        elements.loginTriggerBtn.style.display = "flex";
        elements.userDropdownContainer.style.display = "none";
        document.querySelectorAll(".admin-only-link").forEach(el => el.style.display = "none");
        elements.adminSection.style.display = "none";
    }
}

// Initial UI login check
updateUserUI();

// Open Auth Modal
elements.loginTriggerBtn.addEventListener("click", () => {
    elements.authModal.classList.add("open");
});
elements.btnCloseAuthModal.addEventListener("click", () => {
    elements.authModal.classList.remove("open");
});

// Tab Switch Logic in Auth Modal
elements.authTabs.forEach(tab => {
    tab.addEventListener("click", function() {
        elements.authTabs.forEach(t => t.classList.remove("active"));
        this.classList.add("active");
        
        const tabTarget = this.getAttribute("data-tab");
        document.querySelectorAll(".auth-tab-content").forEach(content => {
            content.classList.remove("active");
        });
        document.getElementById(tabTarget).classList.add("active");
    });
});

// Handle Classic Email/Password Login
elements.loginForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const email = document.getElementById("login-email").value.trim().toLowerCase();
    const password = document.getElementById("login-password").value;
    
    const users = JSON.parse(localStorage.getItem("diaw_shoop_users")) || [];
    const foundUser = users.find(u => u.email === email);
    
    if (foundUser && foundUser.passwordHash === mockHashPassword(password)) {
        sessionStorage.setItem("diaw_shoop_current_user", JSON.stringify(foundUser));
        currentUser = foundUser;
        updateUserUI();
        elements.authModal.classList.remove("open");
        showToast(`Heureux de vous revoir, ${currentUser.name} !`);
    } else {
        showToast("Identifiants incorrects. Veuillez réessayer.", "error");
    }
});

// Handle Classic User registration
elements.registerForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const name = document.getElementById("register-name").value.trim();
    const email = document.getElementById("register-email").value.trim().toLowerCase();
    const password = document.getElementById("register-password").value;
    
    const users = JSON.parse(localStorage.getItem("diaw_shoop_users")) || [];
    if (users.some(u => u.email === email)) {
        showToast("Cet email est déjà enregistré.", "error");
        return;
    }
    
    const newUser = {
        email,
        passwordHash: mockHashPassword(password),
        name,
        isAdmin: false,
        avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(name)}`
    };
    
    users.push(newUser);
    localStorage.setItem("diaw_shoop_users", JSON.stringify(users));
    
    sessionStorage.setItem("diaw_shoop_current_user", JSON.stringify(newUser));
    currentUser = newUser;
    updateUserUI();
    elements.authModal.classList.remove("open");
    showToast(`Compte créé avec succès. Bienvenue, ${name} !`);
});

// Handle simulated Google OAuth flow
elements.btnGoogleLogin.addEventListener("click", () => {
    elements.authModal.classList.remove("open");
    elements.googlePopupOverlay.style.display = "flex";
});

elements.btnCloseGooglePopup.addEventListener("click", () => {
    elements.googlePopupOverlay.style.display = "none";
});

elements.googleAccountItems.forEach(item => {
    item.addEventListener("click", function() {
        const type = this.getAttribute("data-account");
        if (!type) return; // Ignore add account trigger
        
        let simulatedGoogleUser = {};
        const users = JSON.parse(localStorage.getItem("diaw_shoop_users")) || [];
        
        if (type === "superadmin") {
            simulatedGoogleUser = users.find(u => u.email === "mamadoudiaw2005@gmail.com") || {
                email: "mamadoudiaw2005@gmail.com",
                name: "Mamadou Diaw (Grand Admin)",
                isAdmin: true,
                isSuperAdmin: true,
                avatar: "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&q=80&w=100&h=100"
            };
        } else if (type === "admin") {
            simulatedGoogleUser = users.find(u => u.email === "diarra.diaw@diawshoop.sn") || {
                email: "diarra.diaw@diawshoop.sn",
                name: "Diarra Diaw (Admin)",
                isAdmin: true,
                isSuperAdmin: false,
                permissions: { canAddEdit: true, canDelete: false, canManageOrders: true },
                avatar: "https://images.unsplash.com/photo-1580489944761-15a19d654956?auto=format&fit=crop&q=80&w=100&h=100"
            };
        } else {
            simulatedGoogleUser = users.find(u => u.email === "client@gmail.com") || {
                email: "client@gmail.com",
                name: "Awa Ndiaye (Client)",
                isAdmin: false,
                isSuperAdmin: false,
                avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=100&h=100"
            };
        }
        
        // Log in the user
        sessionStorage.setItem("diaw_shoop_current_user", JSON.stringify(simulatedGoogleUser));
        currentUser = simulatedGoogleUser;
        updateUserUI();
        
        elements.googlePopupOverlay.style.display = "none";
        showToast(`Connecté via Google en tant que ${currentUser.name}`);
    });
});

// Simulated Google Custom Account signup/login flow
const btnGoogleAddAccount = document.getElementById("btn-google-add-account");
const btnCancelGoogleAdd = document.getElementById("btn-cancel-google-add");
const btnSubmitGoogleAdd = document.getElementById("btn-submit-google-add");
const googleAccountsList = document.querySelector(".google-accounts-list");
const googleNewAccountForm = document.getElementById("google-new-account-form");

if (btnGoogleAddAccount && googleAccountsList && googleNewAccountForm) {
    btnGoogleAddAccount.addEventListener("click", () => {
        googleAccountsList.style.display = "none";
        btnGoogleAddAccount.style.display = "none";
        googleNewAccountForm.style.display = "flex";
    });
}

if (btnCancelGoogleAdd && googleAccountsList && googleNewAccountForm && btnGoogleAddAccount) {
    btnCancelGoogleAdd.addEventListener("click", () => {
        googleNewAccountForm.style.display = "none";
        googleAccountsList.style.display = "block";
        btnGoogleAddAccount.style.display = "flex";
        // Clear fields
        document.getElementById("google-new-name").value = "";
        document.getElementById("google-new-email").value = "";
    });
}

if (btnSubmitGoogleAdd) {
    btnSubmitGoogleAdd.addEventListener("click", () => {
        const nameInput = document.getElementById("google-new-name");
        const emailInput = document.getElementById("google-new-email");
        
        if (!nameInput || !emailInput) return;
        
        const name = nameInput.value.trim();
        const email = emailInput.value.trim().toLowerCase();
        
        if (!name || !email) {
            showToast("Veuillez remplir tous les champs.", "error");
            return;
        }
        
        const users = JSON.parse(localStorage.getItem("diaw_shoop_users")) || [];
        let matchedUser = users.find(u => u.email === email);
        
        if (!matchedUser) {
            // Register a new Client user
            matchedUser = {
                email,
                name,
                passwordHash: mockHashPassword("google123"), // Default dummy password
                isAdmin: false,
                isSuperAdmin: false,
                avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(name)}`
            };
            users.push(matchedUser);
            localStorage.setItem("diaw_shoop_users", JSON.stringify(users));
        }
        
        // Log in the user
        sessionStorage.setItem("diaw_shoop_current_user", JSON.stringify(matchedUser));
        currentUser = matchedUser;
        updateUserUI();
        
        // Close popups & Reset form
        googleNewAccountForm.style.display = "none";
        googleAccountsList.style.display = "block";
        if (btnGoogleAddAccount) btnGoogleAddAccount.style.display = "flex";
        nameInput.value = "";
        emailInput.value = "";
        
        elements.googlePopupOverlay.style.display = "none";
        showToast(`Créé et connecté avec Google en tant que ${currentUser.name} !`);
    });
}

// Handle Logout
elements.btnLogout.addEventListener("click", (e) => {
    e.preventDefault();
    sessionStorage.removeItem("diaw_shoop_current_user");
    currentUser = null;
    
    // Restore client view visibility in case logout happened in admin dashboard
    const clientHeader = document.getElementById("main-header");
    const clientShopView = document.getElementById("client-shop-view");
    const clientFooter = document.querySelector(".main-footer");
    
    if (clientHeader) clientHeader.style.display = "block";
    if (clientShopView) clientShopView.style.display = "block";
    if (clientFooter) clientFooter.style.display = "block";
    
    updateUserUI();
    showToast("Vous avez été déconnecté.");
});

// --- 6. CATALOGUE INTERACTIVITY (DISPLAY, FILTER, SEARCH) ---
function renderProductList() {
    elements.productsGrid.innerHTML = "";
    
    // Apply filters
    let filtered = products.filter(p => {
        const matchCategory = activeCategory === "all" || p.category === activeCategory;
        const matchSearch = p.name.toLowerCase().includes(searchFilter.toLowerCase()) || 
                            p.description.toLowerCase().includes(searchFilter.toLowerCase());
        return matchCategory && matchSearch;
    });
    
    // Sort
    if (sortOrder === "price-asc") {
        filtered.sort((a, b) => a.price - b.price);
    } else if (sortOrder === "price-desc") {
        filtered.sort((a, b) => b.price - a.price);
    }
    
    // Display results
    if (filtered.length === 0) {
        elements.productsGrid.innerHTML = `
            <div class="loading-spinner-wrapper">
                <i class="fa-solid fa-shirt" style="font-size: 3rem; color: var(--border-color)"></i>
                <p>Aucun produit ne correspond à vos critères.</p>
            </div>
        `;
        return;
    }
    
    filtered.forEach(p => {
        // Calculate rating details
        const prodReviews = reviews.filter(r => r.productId === p.id);
        const reviewsCount = prodReviews.length;
        let ratingHtml = "";
        if (reviewsCount > 0) {
            const avgRating = prodReviews.reduce((sum, r) => sum + r.rating, 0) / reviewsCount;
            ratingHtml = `
                <div class="product-card-rating" style="margin-bottom: 8px; color: #eab308; font-size: 0.8rem; display: flex; align-items: center; gap: 4px; cursor: pointer;" onclick="openProductDetail('${p.id}')">
                    <span style="font-weight: 700;">${avgRating.toFixed(1)}</span>
                    <span><i class="fa-solid fa-star"></i></span>
                    <span style="color: var(--text-muted); font-size: 0.75rem;">(${reviewsCount} avis)</span>
                </div>
            `;
        } else {
            ratingHtml = `
                <div class="product-card-rating" style="margin-bottom: 8px; color: var(--text-muted); font-size: 0.75rem; font-style: italic; cursor: pointer;" onclick="openProductDetail('${p.id}')">
                    Aucun avis
                </div>
            `;
        }

        const card = document.createElement("div");
        card.className = "product-card";
        card.innerHTML = `
            <div class="product-card-image-wrapper" onclick="openProductDetail('${p.id}')">
                <img src="${escapeHTML(p.image)}" alt="${escapeHTML(p.name)}" onerror="this.src='https://placehold.co/400x500?text=${encodeURIComponent(p.name)}'">
            </div>
            <div class="product-card-body">
                <span class="product-category-tag">${escapeHTML(p.category)}</span>
                <h3 class="product-card-title" onclick="openProductDetail('${p.id}')">${escapeHTML(p.name)}</h3>
                ${ratingHtml}
                <div class="product-card-price">${p.price.toLocaleString("fr-FR")} FCFA</div>
            </div>
            <div class="product-card-hover-actions">
                <button class="quick-add-btn" onclick="quickAddToCart('${p.id}')" title="Ajout rapide au panier">
                    <i class="fa-solid fa-plus"></i>
                </button>
            </div>
        `;
        elements.productsGrid.appendChild(card);
    });
}

// Initial render
setTimeout(renderProductList, 500); // Small timeout to show spinner loading effect

// Category Filters Click Events
elements.categoryTabs.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", function() {
        elements.categoryTabs.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
        this.classList.add("active");
        activeCategory = this.getAttribute("data-category");
        renderProductList();
    });
});

// Search functionality (Safeguarded)
function handleSearch() {
    if (!elements.searchInput) return;
    searchFilter = elements.searchInput.value.trim();
    if (searchFilter) {
        if (elements.activeFiltersInfo) elements.activeFiltersInfo.style.display = "flex";
        if (elements.searchQueryText) elements.searchQueryText.textContent = searchFilter;
    } else {
        if (elements.activeFiltersInfo) elements.activeFiltersInfo.style.display = "none";
    }
    renderProductList();
}
if (elements.searchBtn) {
    elements.searchBtn.addEventListener("click", handleSearch);
}
if (elements.searchInput) {
    elements.searchInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") handleSearch();
    });
}
if (elements.clearSearchBtn) {
    elements.clearSearchBtn.addEventListener("click", () => {
        if (elements.searchInput) elements.searchInput.value = "";
        searchFilter = "";
        if (elements.activeFiltersInfo) elements.activeFiltersInfo.style.display = "none";
        renderProductList();
    });
}

// Sorting Event
elements.sortSelect.addEventListener("change", function() {
    sortOrder = this.value;
    renderProductList();
});

// --- 7. DETAILED PRODUCT MODAL & WHATSAPP GENERATION ---
let currentDetailProduct = null;
let selectedSize = null;

function openProductDetail(id) {
    currentDetailProduct = products.find(p => p.id === id);
    if (!currentDetailProduct) return;
    
    selectedSize = null; // reset
    
    // Set media content (Image or Video)
    elements.modalMediaContainer.innerHTML = "";
    
    if (currentDetailProduct.videoUrl) {
        const vUrl = currentDetailProduct.videoUrl.trim();
        // Check if YouTube
        if (vUrl.includes("youtube.com") || vUrl.includes("youtu.be")) {
            let embedUrl = vUrl;
            if (vUrl.includes("watch?v=")) {
                const vid = vUrl.split("watch?v=")[1].split("&")[0];
                embedUrl = `https://www.youtube.com/embed/${vid}`;
            } else if (vUrl.includes("youtu.be/")) {
                const vid = vUrl.split("youtu.be/")[1].split("?")[0];
                embedUrl = `https://www.youtube.com/embed/${vid}`;
            }
            elements.modalMediaContainer.innerHTML = `
                <iframe src="${embedUrl}" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen style="width:100%; height:100%; min-height:350px; border-radius:8px;"></iframe>
            `;
        } else {
            // Direct MP4 link
            elements.modalMediaContainer.innerHTML = `
                <video src="${escapeHTML(vUrl)}" controls autoplay muted loop style="width:100%; height:100%; min-height:350px; object-fit:cover; border-radius:8px;"></video>
            `;
        }
    } else {
        // Fallback to static image
        const img = document.createElement("img");
        img.src = currentDetailProduct.image;
        img.alt = currentDetailProduct.name;
        img.id = "modal-product-image";
        img.onerror = function() {
            this.src = `https://placehold.co/500x600?text=${encodeURIComponent(currentDetailProduct.name)}`;
        };
        elements.modalMediaContainer.appendChild(img);
    }
    
    elements.modalProductCategory.textContent = currentDetailProduct.category.toUpperCase();
    elements.modalProductTitle.textContent = currentDetailProduct.name;
    elements.modalProductPrice.textContent = `${currentDetailProduct.price.toLocaleString("fr-FR")} FCFA`;
    elements.modalProductDesc.textContent = currentDetailProduct.description;
    
    // Sizing Interface conditional by category
    const isClothing = currentDetailProduct.category === "vetements" || currentDetailProduct.category === "robes";
    const sizeWrapper = document.getElementById("modal-size-selection-wrapper");
    
    if (!isClothing) {
        if (sizeWrapper) sizeWrapper.style.display = "none";
        selectedSize = "U";
        
        // Stock Display for unique size products
        const qty = currentDetailProduct.stocks ? (currentDetailProduct.stocks.S || 0) : 0;
        updateStockDisplay(qty);
    } else {
        if (sizeWrapper) sizeWrapper.style.display = "block";
        selectedSize = null;
        
        elements.sizeOptionsContainer.innerHTML = "";
        const sizeKeys = ["S", "M", "L", "XL"];
        
        sizeKeys.forEach(sz => {
            const stock = currentDetailProduct.stocks ? currentDetailProduct.stocks[sz] : 0;
            const btn = document.createElement("button");
            btn.className = "size-btn";
            btn.textContent = sz;
            
            if (stock <= 0) {
                btn.classList.add("disabled");
                btn.title = "Rupture de stock";
            } else {
                btn.addEventListener("click", () => {
                    document.querySelectorAll(".size-options .size-btn").forEach(b => b.classList.remove("active"));
                    btn.classList.add("active");
                    selectedSize = sz;
                    updateStockDisplay(stock);
                });
            }
            elements.sizeOptionsContainer.appendChild(btn);
        });
        
        elements.modalStockStatus.textContent = "Sélectionnez une taille pour voir la disponibilité.";
        elements.modalStockStatus.style.color = "var(--text-muted)";
    }
    
    renderProductReviews(id);
    
    elements.productDetailModal.classList.add("open");
}

function updateStockDisplay(qty) {
    if (qty > 5) {
        elements.modalStockStatus.innerHTML = `<i class="fa-solid fa-circle-check"></i> En Stock (${qty} disponibles)`;
        elements.modalStockStatus.style.color = "var(--success)";
    } else if (qty > 0) {
        elements.modalStockStatus.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> Stock Limité (Seulement ${qty} restants)`;
        elements.modalStockStatus.style.color = "var(--om-orange)";
    } else {
        elements.modalStockStatus.innerHTML = `<i class="fa-solid fa-circle-xmark"></i> Rupture de stock`;
        elements.modalStockStatus.style.color = "var(--free-red)";
    }
}

elements.btnCloseProductModal.addEventListener("click", () => {
    elements.productDetailModal.classList.remove("open");
});

// Add to Cart inside detail view
elements.modalBtnAddCart.addEventListener("click", () => {
    if (!currentDetailProduct) return;
    if (!selectedSize) {
        showToast("Veuillez sélectionner une taille (S, M, L, XL) avant de l'ajouter.", "error");
        return;
    }
    
    addToCart(currentDetailProduct.id, selectedSize);
    elements.productDetailModal.classList.remove("open");
});

// WhatsApp Direct Purchase order (Senegal specific conversion optimization)
elements.modalBtnWhatsapp.addEventListener("click", () => {
    if (!currentDetailProduct) return;
    if (!selectedSize) {
        showToast("Veuillez sélectionner une taille avant de commander via WhatsApp.", "error");
        return;
    }
    
    const shopSettings = JSON.parse(localStorage.getItem("diaw_shoop_settings")) || { whatsapp: "221785946427" };
    const sizeText = selectedSize === "U" ? "" : `\n- *Taille* : ${selectedSize}`;
    const message = `Bonjour DIAW SHOOP ! Je souhaite commander cet article :
- *Produit* : ${currentDetailProduct.name}${sizeText}
- *Prix* : ${currentDetailProduct.price.toLocaleString("fr-FR")} FCFA

Merci de me confirmer sa disponibilité !`;

    const encoded = encodeURIComponent(message);
    const waUrl = `https://wa.me/${shopSettings.whatsapp}?text=${encoded}`;
    window.open(waUrl, "_blank");
});

// Quick Add to Cart helper (from the grid directly, picks first available size or asks to open detail)
function quickAddToCart(productId) {
    const prod = products.find(p => p.id === productId);
    if (!prod) return;
    
    const isClothing = prod.category === "vetements" || prod.category === "robes";
    if (!isClothing) {
        const stock = prod.stocks ? (prod.stocks.S || 0) : 0;
        if (stock > 0) {
            addToCart(productId, "U");
        } else {
            openProductDetail(productId);
        }
        return;
    }
    
    // Find first size with positive stock
    let sizeFound = null;
    const sizes = ["M", "S", "L", "XL"]; // Prefer standard M/S first
    for (let s of sizes) {
        if (prod.stocks && prod.stocks[s] > 0) {
            sizeFound = s;
            break;
        }
    }
    
    if (sizeFound) {
        addToCart(productId, sizeFound);
    } else {
        // Open details modal if no stock or accessory
        openProductDetail(productId);
    }
}

// --- 8. SHOPPING CART MANAGEMENT ---
function addToCart(id, size) {
    const prod = products.find(p => p.id === id);
    if (!prod) return;
    
    // Check if item is already in cart
    const existing = cart.find(item => item.id === id && item.size === size);
    
    // Check stock limit (fallback to S stock for Unique 'U' items)
    const currentStock = prod.stocks ? (prod.stocks[size] || prod.stocks.S || 99) : 99;
    
    if (existing) {
        if (existing.qty >= currentStock) {
            const errorMsg = size === "U" ? "Désolé, stock insuffisant pour cet article." : `Désolé, stock insuffisant pour la taille ${size}.`;
            showToast(errorMsg, "error");
            return;
        }
        existing.qty += 1;
    } else {
        cart.push({
            id: prod.id,
            name: prod.name,
            price: prod.price,
            image: prod.image,
            size: size,
            qty: 1
        });
    }
    
    saveCart();
    renderCart();
    elements.cartSidebar.classList.add("open");
    elements.sidebarOverlay.classList.add("open");
    showToast(`"${prod.name} (${size})" ajouté au panier !`);
}

function saveCart() {
    localStorage.setItem("diaw_shoop_cart", JSON.stringify(cart));
}

function renderCart() {
    // 1. Update Badge counts
    const totalItems = cart.reduce((sum, item) => sum + item.qty, 0);
    elements.cartBadge.textContent = totalItems;
    
    if (cart.length === 0) {
        elements.cartSidebarBody.innerHTML = `
            <div class="empty-cart-message">
                <i class="fa-solid fa-bag-shopping empty-icon"></i>
                <p>Votre panier est vide.</p>
                <button class="btn btn-primary" id="btn-cart-continue">Commencer vos achats</button>
            </div>
        `;
        // Re-attach close dynamic listener inside guest body
        const btnContinue = document.getElementById("btn-cart-continue");
        if (btnContinue) {
            btnContinue.addEventListener("click", () => {
                elements.cartSidebar.classList.remove("open");
                elements.sidebarOverlay.classList.remove("open");
            });
        }
        elements.cartSidebarFooter.style.display = "none";
        return;
    }
    
    elements.cartSidebarFooter.style.display = "block";
    elements.cartSidebarBody.innerHTML = "";
    
    // Render list items
    cart.forEach(item => {
        const itemEl = document.createElement("div");
        itemEl.className = "cart-item";
        itemEl.innerHTML = `
            <img src="${escapeHTML(item.image)}" alt="${escapeHTML(item.name)}" class="cart-item-image">
            <div class="cart-item-info">
                <h4 class="cart-item-title">${escapeHTML(item.name)}</h4>
                <span class="cart-item-size" style="${item.size === 'U' ? 'display:none;' : ''}">Taille : ${item.size}</span>
                <span class="cart-item-price">${(item.price * item.qty).toLocaleString("fr-FR")} F</span>
                <div class="cart-item-qty">
                    <button class="qty-btn" onclick="updateCartQty('${item.id}', '${item.size}', -1)"><i class="fa-solid fa-minus"></i></button>
                    <span class="qty-val">${item.qty}</span>
                    <button class="qty-btn" onclick="updateCartQty('${item.id}', '${item.size}', 1)"><i class="fa-solid fa-plus"></i></button>
                </div>
            </div>
            <button class="remove-item-btn" onclick="removeFromCart('${item.id}', '${item.size}')"><i class="fa-solid fa-trash-can"></i></button>
        `;
        elements.cartSidebarBody.appendChild(itemEl);
    });
    
    calculateCartTotals();
}

function updateCartQty(id, size, change) {
    const item = cart.find(i => i.id === id && i.size === size);
    if (!item) return;
    
    const prod = products.find(p => p.id === id);
    const stockLimit = prod ? prod.stocks[size] : 99;
    
    if (change > 0 && item.qty >= stockLimit) {
        showToast("Impossible d'ajouter plus d'articles. Stock maximum atteint.", "error");
        return;
    }
    
    item.qty += change;
    if (item.qty <= 0) {
        removeFromCart(id, size);
        return;
    }
    
    saveCart();
    renderCart();
}

function removeFromCart(id, size) {
    cart = cart.filter(item => !(item.id === id && item.size === size));
    saveCart();
    renderCart();
    showToast("Article retiré du panier.", "info");
}

function calculateCartTotals() {
    const subtotal = cart.reduce((sum, item) => sum + (item.price * item.qty), 0);
    
    // Shipping Zone calculation
    const zone = elements.cartDeliveryZone.value;
    let shipping = 1500; // default dakar centre
    if (zone === "dakar-banlieue") shipping = 2500;
    if (zone === "regions") shipping = 4000;
    
    // Wave announcement discount logic: free dakar shipping for basket > 35,000 F
    if (subtotal >= 35000 && zone !== "regions") {
        shipping = 0;
    }
    
    const total = subtotal + shipping;
    
    elements.cartSubtotal.textContent = `${subtotal.toLocaleString("fr-FR")} FCFA`;
    elements.cartShippingCost.textContent = shipping === 0 ? "GRATUIT" : `${shipping.toLocaleString("fr-FR")} FCFA`;
    elements.cartTotal.textContent = `${total.toLocaleString("fr-FR")} FCFA`;
    
    // Save to global checkout state
    checkoutDetails.subtotal = subtotal;
    checkoutDetails.shippingCost = shipping;
    checkoutDetails.total = total;
    checkoutDetails.deliveryZone = zone;
    checkoutDetails.items = [...cart];
}

// Cart Drawer open/close events
elements.cartTriggerBtn.addEventListener("click", () => {
    elements.cartSidebar.classList.add("open");
    elements.sidebarOverlay.classList.add("open");
});

const closeCartHandler = () => {
    elements.cartSidebar.classList.remove("open");
    elements.sidebarOverlay.classList.remove("open");
};
elements.closeCartBtn.addEventListener("click", closeCartHandler);
elements.sidebarOverlay.addEventListener("click", closeCartHandler);
elements.cartDeliveryZone.addEventListener("change", calculateCartTotals);

// Initial Cart rendering
renderCart();

// Trigger Checkout (requires login check first)
elements.btnCheckoutTrigger.addEventListener("click", () => {
    if (!currentUser) {
        showToast("Veuillez vous connecter à votre compte client pour passer une commande.", "info");
        elements.authModal.classList.add("open");
        return;
    }
    
    // Populate form with logged in user details if guest registers
    document.getElementById("checkout-name").value = currentUser.name || "";
    document.getElementById("checkout-email").value = currentUser.email || "";
    
    // Update summary amount text
    elements.checkoutAmountSummary.textContent = `${checkoutDetails.total.toLocaleString("fr-FR")} FCFA`;
    
    // Open checkout modal
    elements.cartSidebar.classList.remove("open");
    elements.sidebarOverlay.classList.remove("open");
    
    // Reset steps UI
    setCheckoutStep(1);
    elements.checkoutModal.classList.add("open");
});

elements.btnCloseCheckoutModal.addEventListener("click", () => {
    elements.checkoutModal.classList.remove("open");
});

// --- 9. SECURED SENEGALESE MOBILE PAYMENT SIMULATION ---
function setCheckoutStep(stepNumber) {
    document.querySelectorAll(".checkout-step-content").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".checkout-steps .step").forEach((el, index) => {
        el.classList.remove("active", "completed");
        if (index + 1 === stepNumber) {
            el.classList.add("active");
        } else if (index + 1 < stepNumber) {
            el.classList.add("completed");
        }
    });
    
    document.getElementById(`checkout-step-${stepNumber}`).classList.add("active");
}

// STEP 1 Form submit
elements.shippingInfoForm.addEventListener("submit", (e) => {
    e.preventDefault();
    
    // Secure input validation and sanitation
    const name = document.getElementById("checkout-name").value.trim();
    const phone = document.getElementById("checkout-phone").value.trim();
    const email = document.getElementById("checkout-email").value.trim();
    const address = document.getElementById("checkout-address").value.trim();
    const notes = document.getElementById("checkout-notes").value.trim();
    
    // Validate Senegalese number formats (9 digits, starts with 77, 78, 76, 75, 70)
    const phoneCleaned = phone.replace(/\s+/g, '');
    const senegalPhoneRegex = /^(77|78|76|75|70)\d{7}$/;
    
    if (!senegalPhoneRegex.test(phoneCleaned)) {
        showToast("Numéro de téléphone invalide. Veuillez entrer un numéro à 9 chiffres valide au Sénégal (commençant par 77, 78, 76, 75 ou 70).", "error");
        return;
    }
    
    checkoutDetails.name = name;
    checkoutDetails.phone = phoneCleaned;
    checkoutDetails.email = email;
    checkoutDetails.address = address;
    checkoutDetails.notes = notes;
    
    setCheckoutStep(2);
});

elements.btnBackToStep1.addEventListener("click", () => setCheckoutStep(1));

// STEP 2 Payment Method Selection
let selectedPaymentMethod = "";
document.querySelectorAll(".payment-method-card").forEach(card => {
    card.addEventListener("click", function() {
        document.querySelectorAll(".payment-method-card").forEach(c => c.classList.remove("active"));
        this.classList.add("active");
        selectedPaymentMethod = this.getAttribute("data-method");
        checkoutDetails.paymentMethod = selectedPaymentMethod;
    });
});

elements.btnBackToStep2.addEventListener("click", () => {
    // Reset wizard displays
    document.querySelectorAll(".payment-wizard").forEach(w => w.style.display = "none");
    elements.simNavButtons.style.display = "flex";
    setCheckoutStep(2);
});

elements.btnProceedToSim.addEventListener("click", () => {
    if (!selectedPaymentMethod) {
        showToast("Veuillez sélectionner un moyen de paiement pour continuer.", "error");
        return;
    }
    
    setCheckoutStep(3);
    document.querySelectorAll(".payment-wizard").forEach(w => w.style.display = "none");
    
    // Load wizard
    if (selectedPaymentMethod === "wave" || selectedPaymentMethod === "om" || selectedPaymentMethod === "free") {
        document.getElementById("wizard-online-payment").style.display = "block";
        document.getElementById("online-payment-amount").textContent = `${checkoutDetails.total.toLocaleString("fr-FR")} FCFA`;
        document.getElementById("online-payment-btn-amount").textContent = `${checkoutDetails.total.toLocaleString("fr-FR")} F`;
        
        let methodLabel = "Wave Sénégal";
        if (selectedPaymentMethod === "om") methodLabel = "Orange Money";
        if (selectedPaymentMethod === "free") methodLabel = "Free Money";
        document.getElementById("online-payment-method").textContent = methodLabel;
    } else if (selectedPaymentMethod === "cash") {
        document.getElementById("wizard-cash").style.display = "block";
        document.getElementById("cash-amount-confirm").textContent = `${checkoutDetails.total.toLocaleString("fr-FR")} FCFA`;
    }
});

// --- CINETPAY ONLINE PAYMENT SYSTEM ---
let paymentPollingInterval = null;

// Trigger CinetPay checkout request
const btnTriggerOnlinePayment = document.getElementById("btn-trigger-online-payment");
const btnCancelOnlinePolling = document.getElementById("btn-cancel-online-polling");

if (btnTriggerOnlinePayment) {
    btnTriggerOnlinePayment.addEventListener("click", () => {
        if (!checkoutDetails || !checkoutDetails.total) return;
        
        // Hide payment wizard and show verification loader
        document.getElementById("wizard-online-payment").style.display = "none";
        document.getElementById("wizard-online-pending").style.display = "block";
        elements.simNavButtons.style.display = "none"; // Hide Back to choice button
        
        const settings = JSON.parse(localStorage.getItem("diaw_shoop_settings")) || {};
        const payoutNumber = settings.payoutNumber || "770000000";
        const payoutCarrier = settings.payoutCarrier || "wave";
        
        fetch("/api/create-payment", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                amount: checkoutDetails.total,
                customer_name: checkoutDetails.name,
                customer_phone: checkoutDetails.phone,
                customer_email: checkoutDetails.email,
                payout_number: payoutNumber,
                payout_carrier: payoutCarrier,
                items: checkoutDetails.items.map(it => ({ id: it.id, name: it.name, qty: it.qty, price: it.price, size: it.size }))
            })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                const paymentUrl = data.payment_url;
                const transactionId = data.transaction_id;
                
                // Open CinetPay hosted gateway checkout in new tab
                const win = window.open(paymentUrl, "_blank");
                if (!win) {
                    showToast("Veuillez autoriser les fenêtres pop-ups pour accéder à la page de paiement.", "warning");
                }
                
                // Start polling backend for verification
                startPaymentPolling(transactionId);
            } else {
                showToast(data.message || "Erreur d'initialisation de la transaction.", "error");
                document.getElementById("wizard-online-payment").style.display = "block";
                document.getElementById("wizard-online-pending").style.display = "none";
                elements.simNavButtons.style.display = "flex";
            }
        })
        .catch(err => {
            console.error("CinetPay Create Payment Exception:", err);
            showToast("Erreur de connexion avec le serveur de paiement.", "error");
            document.getElementById("wizard-online-payment").style.display = "block";
            document.getElementById("wizard-online-pending").style.display = "none";
            elements.simNavButtons.style.display = "flex";
        });
    });
}

function startPaymentPolling(transactionId) {
    if (paymentPollingInterval) clearInterval(paymentPollingInterval);
    
    const titleEl = document.getElementById("online-pending-title");
    const descEl = document.getElementById("online-pending-desc");
    if (titleEl) titleEl.textContent = "Attente du paiement...";
    if (descEl) descEl.innerHTML = `Veuillez finaliser le paiement sur l'onglet CinetPay.<br>Nous vérifions en temps réel la validation sur votre téléphone.`;

    paymentPollingInterval = setInterval(() => {
        fetch(`/api/payment-status/${transactionId}`)
        .then(res => res.json())
        .then(data => {
            if (data.status === "success" && data.payment_status === "ACCEPTED") {
                clearInterval(paymentPollingInterval);
                paymentPollingInterval = null;
                
                showToast("Paiement reçu et validé avec succès !", "success");
                finalizeOnlineOrder(transactionId, data.payment_method || checkoutDetails.paymentMethod);
            } else if (data.payment_status === "REFUSED") {
                clearInterval(paymentPollingInterval);
                paymentPollingInterval = null;
                showToast("Le paiement a été refusé ou annulé.", "error");
                
                document.getElementById("wizard-online-payment").style.display = "block";
                document.getElementById("wizard-online-pending").style.display = "none";
                elements.simNavButtons.style.display = "flex";
            }
        })
        .catch(err => console.error("Error checking CinetPay status:", err));
    }, 3500);
}

if (btnCancelOnlinePolling) {
    btnCancelOnlinePolling.addEventListener("click", () => {
        if (paymentPollingInterval) {
            clearInterval(paymentPollingInterval);
            paymentPollingInterval = null;
        }
        showToast("Transaction annulée par l'utilisateur.", "error");
        document.getElementById("wizard-online-payment").style.display = "block";
        document.getElementById("wizard-online-pending").style.display = "none";
        elements.simNavButtons.style.display = "flex";
    });
}

function finalizeOnlineOrder(transactionId, paymentMethodUsed) {
    // 1. Create order
    const orderDate = new Date().toLocaleString("fr-FR");
    const newOrder = {
        id: transactionId,
        date: orderDate,
        clientEmail: currentUser.email,
        clientName: checkoutDetails.name,
        clientPhone: checkoutDetails.phone,
        clientAddress: checkoutDetails.address,
        notes: checkoutDetails.notes,
        items: checkoutDetails.items,
        subtotal: checkoutDetails.subtotal,
        shippingCost: checkoutDetails.shippingCost,
        total: checkoutDetails.total,
        paymentMethod: paymentMethodUsed.toUpperCase(),
        reference: transactionId,
        status: "Payée (En attente d'expédition)"
    };
    
    // 2. Decrement physical stock
    checkoutDetails.items.forEach(cartItem => {
        const p = products.find(prod => prod.id === cartItem.id);
        const targetSize = cartItem.size === "U" ? "S" : cartItem.size;
        if (p && p.stocks && p.stocks[targetSize]) {
            p.stocks[targetSize] = Math.max(0, p.stocks[targetSize] - cartItem.qty);
        }
    });
    localStorage.setItem("diaw_shoop_products", JSON.stringify(products));
    renderProductList();
    
    // 3. Save order locally
    orders.unshift(newOrder);
    localStorage.setItem("diaw_shoop_orders", JSON.stringify(orders));
    
    // 4. Generate ticket invoice
    renderInvoiceTicket(newOrder);
    
    // 5. Clear cart
    cart = [];
    saveCart();
    renderCart();
    
    // 6. Go to final receipt step
    setCheckoutStep(4);
    
    // Refresh admin dashboard if open
    if (currentUser && currentUser.isAdmin) {
        renderAdminDashboard();
    }
}

// CASH ON DELIVERY WIZARD CONTROLLER
const btnCashConfirmOrder = document.getElementById("btn-cash-confirm-order");
if (btnCashConfirmOrder) {
    btnCashConfirmOrder.addEventListener("click", () => {
        executeSimulatedTransaction("CASH_COD_" + Math.random().toString(36).substr(2, 6).toUpperCase());
    });
}

// RUN TRANSACTION PROCESSOR
function executeSimulatedTransaction(referenceCode) {
    // Hide wizard options and actions
    document.querySelectorAll(".payment-wizard").forEach(w => w.style.display = "none");
    elements.simNavButtons.style.display = "none";
    elements.transactionLoader.style.display = "flex";
    
    // Simulate transaction delay
    setTimeout(() => {
        elements.transactionLoader.style.display = "none";
        
        // 1. Create Order object
        const orderId = "DS-" + Math.floor(100000 + Math.random() * 900000);
        const orderDate = new Date().toLocaleString("fr-FR");
        
        const newOrder = {
            id: orderId,
            date: orderDate,
            clientEmail: currentUser.email,
            clientName: checkoutDetails.name,
            clientPhone: checkoutDetails.phone,
            clientAddress: checkoutDetails.address,
            notes: checkoutDetails.notes,
            items: checkoutDetails.items,
            subtotal: checkoutDetails.subtotal,
            shippingCost: checkoutDetails.shippingCost,
            total: checkoutDetails.total,
            paymentMethod: checkoutDetails.paymentMethod.toUpperCase(),
            reference: referenceCode,
            status: checkoutDetails.paymentMethod === "cash" ? "Reçue (Paiement à la livraison)" : "Payée (En attente d'expédition)"
        };
        
        // 2. Decrement physical inventory stock for ordered sizes
        checkoutDetails.items.forEach(cartItem => {
            const p = products.find(prod => prod.id === cartItem.id);
            const targetSize = cartItem.size === "U" ? "S" : cartItem.size;
            if (p && p.stocks && p.stocks[targetSize]) {
                p.stocks[targetSize] = Math.max(0, p.stocks[targetSize] - cartItem.qty);
            }
        });
        localStorage.setItem("diaw_shoop_products", JSON.stringify(products));
        renderProductList(); // Refresh main view
        
        // 3. Save order locally
        orders.unshift(newOrder);
        localStorage.setItem("diaw_shoop_orders", JSON.stringify(orders));
        
        // 4. Generate invoice receipt ticket
        renderInvoiceTicket(newOrder);
        
        // 5. Clear cart
        cart = [];
        saveCart();
        renderCart();
        
        // 6. Go to final receipt step
        setCheckoutStep(4);
        showToast("Votre paiement a été validé ! Commande enregistrée.");
        
        // Refresh admin if logged in
        if (currentUser.isAdmin) {
            renderAdminDashboard();
        }
    }, 2500);
}

function renderInvoiceTicket(order) {
    let itemsRowsHtml = "";
    order.items.forEach(it => {
        const displaySize = it.size === "U" ? "" : ` (${it.size})`;
        itemsRowsHtml += `
            <div class="invoice-row">
                <span>${escapeHTML(it.name)}${displaySize} x${it.qty}</span>
                <span>${(it.price * it.qty).toLocaleString("fr-FR")} F</span>
            </div>
        `;
    });
    
    elements.invoiceReceiptDetails.innerHTML = `
        <div class="invoice-title">TICKET DE COMMANDE</div>
        <div class="invoice-row">
            <span><strong>N° Commande :</strong></span>
            <span>${order.id}</span>
        </div>
        <div class="invoice-row">
            <span><strong>Date :</strong></span>
            <span>${order.date}</span>
        </div>
        <div class="invoice-row divider">
            <span><strong>Transaction :</strong></span>
            <span style="color: var(--accent-dark); font-weight:bold;">${order.reference}</span>
        </div>
        
        <div class="invoice-row">
            <span><strong>Destinataire :</strong></span>
            <span>${escapeHTML(order.clientName)}</span>
        </div>
        <div class="invoice-row">
            <span><strong>Téléphone :</strong></span>
            <span>+221 ${escapeHTML(order.clientPhone)}</span>
        </div>
        <div class="invoice-row divider">
            <span><strong>Adresse :</strong></span>
            <span>${escapeHTML(order.clientAddress)}</span>
        </div>
        
        ${itemsRowsHtml}
        
        <div class="invoice-row divider" style="margin-top: 10px;">
            <span>Frais de livraison (${order.shippingCost === 0 ? 'Offert' : 'Standard'}) :</span>
            <span>${order.shippingCost.toLocaleString("fr-FR")} F</span>
        </div>
        <div class="invoice-row total">
            <span>TOTAL REGLE :</span>
            <span>${order.total.toLocaleString("fr-FR")} FCFA</span>
        </div>
        <div class="invoice-row" style="margin-top: 10px; font-size: 0.75rem; color: var(--text-muted);">
            <span>Mode : ${order.paymentMethod}</span>
            <span>Statut : ${order.status}</span>
        </div>
    `;
}

elements.btnCheckoutCloseComplete.addEventListener("click", () => {
    elements.checkoutModal.classList.remove("open");
});

elements.btnDownloadPdf.addEventListener("click", () => {
    showToast("Reçu de commande téléchargé (Simulation PDF).", "info");
});

// --- 10. USER HISTORIQUE ORDER VIEW ---
elements.btnMyOrders.addEventListener("click", (e) => {
    e.preventDefault();
    if (!currentUser) return;
    
    const clientOrders = orders.filter(o => o.clientEmail === currentUser.email);
    elements.myOrdersList.innerHTML = "";
    
    if (clientOrders.length === 0) {
        elements.myOrdersList.innerHTML = `
            <div style="text-align:center; padding: 40px; color: var(--text-muted)">
                <i class="fa-solid fa-clock-rotate-left" style="font-size: 2.5rem; margin-bottom:15px;"></i>
                <p>Vous n'avez pas encore passé de commande sur notre boutique.</p>
            </div>
        `;
    } else {
        clientOrders.forEach(o => {
            let itemDetails = o.items.map(it => it.size === "U" ? `${escapeHTML(it.name)} x${it.qty}` : `${escapeHTML(it.name)} (${it.size}) x${it.qty}`).join(", ");
            const card = document.createElement("div");
            card.className = "customer-order-card";
            card.innerHTML = `
                <div class="order-card-header">
                    <span><strong>Ref: ${o.id}</strong> | ${o.date}</span>
                    <span class="badge ${o.status.includes('Payée') || o.status.includes('Livré') ? 'badge-success' : 'badge-accent'}">${escapeHTML(o.status)}</span>
                </div>
                <div style="font-size: 0.85rem; color: var(--text-muted);">
                    <p><strong>Articles :</strong> ${itemDetails}</p>
                    <p><strong>Adresse :</strong> ${escapeHTML(o.clientAddress)}</p>
                </div>
                <div class="order-card-footer">
                    <span>Total :</span>
                    <span>${o.total.toLocaleString("fr-FR")} FCFA</span>
                </div>
            `;
            elements.myOrdersList.appendChild(card);
        });
    }
    
    elements.myOrdersModal.classList.add("open");
});

const closeOrdersModal = () => elements.myOrdersModal.classList.remove("open");
elements.btnCloseMyOrders.addEventListener("click", closeOrdersModal);
elements.btnCloseMyOrdersBtn.addEventListener("click", closeOrdersModal);

// --- 11. SECURED ROLE-BASED ADMIN DASHBOARD CONTROLLERS ---
// Nav links to scroll/open admin
elements.navAdmin.addEventListener("click", (e) => {
    e.preventDefault();
    openAdminDashboard();
});
elements.dropdownAdminBtn.addEventListener("click", (e) => {
    e.preventDefault();
    openAdminDashboard();
});

function openAdminDashboard() {
    if (!currentUser || !currentUser.isAdmin) {
        showToast("Accès refusé. Autorisation administrateur requise.", "error");
        return;
    }
    
    // Hide client layout components
    const clientHeader = document.getElementById("main-header");
    const clientShopView = document.getElementById("client-shop-view");
    const clientFooter = document.querySelector(".main-footer");
    
    if (clientHeader) clientHeader.style.display = "none";
    if (clientShopView) clientShopView.style.display = "none";
    if (clientFooter) clientFooter.style.display = "none";
    
    // Show admin view
    elements.adminSection.style.display = "block";
    renderAdminDashboard();
    if (currentUser.isSuperAdmin) {
        applyStoreSettings();
    }
    
    window.scrollTo({
        top: 0,
        behavior: "instant"
    });
}

elements.btnCloseAdmin.addEventListener("click", () => {
    // Show client layout components
    const clientHeader = document.getElementById("main-header");
    const clientShopView = document.getElementById("client-shop-view");
    const clientFooter = document.querySelector(".main-footer");
    
    if (clientHeader) clientHeader.style.display = "block";
    if (clientShopView) clientShopView.style.display = "block";
    if (clientFooter) clientFooter.style.display = "block";
    
    elements.adminSection.style.display = "none";
    
    window.scrollTo({
        top: 0,
        behavior: "instant"
    });
});

const btnAdminLogout = document.getElementById("btn-admin-logout");
if (btnAdminLogout) {
    btnAdminLogout.addEventListener("click", () => {
        sessionStorage.removeItem("diaw_shoop_current_user");
        currentUser = null;
        
        // Show client layout components
        const clientHeader = document.getElementById("main-header");
        const clientShopView = document.getElementById("client-shop-view");
        const clientFooter = document.querySelector(".main-footer");
        
        if (clientHeader) clientHeader.style.display = "block";
        if (clientShopView) clientShopView.style.display = "block";
        if (clientFooter) clientFooter.style.display = "block";
        
        elements.adminSection.style.display = "none";
        
        updateUserUI();
        showToast("Vous avez été déconnecté.");
        
        window.scrollTo({
            top: 0,
            behavior: "instant"
        });
    });
}

// Admin Tab switcher
document.querySelectorAll(".admin-tab-btn").forEach(btn => {
    btn.addEventListener("click", function() {
        document.querySelectorAll(".admin-tab-btn").forEach(b => b.classList.remove("active"));
        this.classList.add("active");
        
        const target = this.getAttribute("data-target");
        document.querySelectorAll(".admin-tab-content").forEach(content => {
            content.classList.remove("active");
        });
        document.getElementById(target).classList.add("active");
    });
});

// Preset selection behavior
elements.prodImagePresetSelect.addEventListener("change", function() {
    const customOptions = document.getElementById("custom-image-options");
    if (this.value === "custom") {
        if (customOptions) customOptions.style.display = "flex";
        if (elements.prodImageUrlInput) {
            elements.prodImageUrlInput.style.display = "block";
            elements.prodImageUrlInput.required = !customImageBase64;
        }
    } else {
        if (customOptions) customOptions.style.display = "none";
        if (elements.prodImageUrlInput) {
            elements.prodImageUrlInput.style.display = "none";
            elements.prodImageUrlInput.required = false;
            elements.prodImageUrlInput.value = "";
        }
        if (elements.prodImageFileInput) elements.prodImageFileInput.value = "";
        customImageBase64 = "";
    }
});

// Local file uploader handlers
if (elements.prodImageFileInput) {
    elements.prodImageFileInput.addEventListener("change", function(e) {
        const file = e.target.files[0];
        if (file) {
            if (file.size > 2 * 1024 * 1024) {
                showToast("Attention : L'image dépasse 2 Mo. Elle risque de ralentir le chargement.", "warning");
            }
            const reader = new FileReader();
            reader.onload = function(evt) {
                customImageBase64 = evt.target.result;
                if (elements.prodImageUrlInput) {
                    elements.prodImageUrlInput.value = ""; // Clear text URL if file selected
                    elements.prodImageUrlInput.required = false;
                }
            };
            reader.readAsDataURL(file);
        }
    });
}

if (elements.prodVideoFileInput) {
    elements.prodVideoFileInput.addEventListener("change", function(e) {
        const file = e.target.files[0];
        if (file) {
            if (file.size > 10 * 1024 * 1024) {
                showToast("Attention : La vidéo dépasse 10 Mo. Nous conseillons une vidéo plus courte pour le stockage.", "warning");
            }
            const reader = new FileReader();
            reader.onload = function(evt) {
                customVideoBase64 = evt.target.result;
                if (elements.prodVideoInput) {
                    elements.prodVideoInput.value = ""; // Clear text URL if file selected
                }
            };
            reader.readAsDataURL(file);
        }
    });
}

// Calculate statistics
function renderAdminDashboard() {
    if (!currentUser || !currentUser.isAdmin) return;

    // 1. Resolve active user permissions
    const isSuper = currentUser.isSuperAdmin === true;
    
    // In localstorage users list, secondary admins might have permissions updated by super admin
    let userPermissions = { canAddEdit: true, canDelete: true, canManageOrders: true };
    if (!isSuper) {
        const users = JSON.parse(localStorage.getItem("diaw_shoop_users")) || [];
        const found = users.find(u => u.email === currentUser.email);
        if (found && found.permissions) {
            userPermissions = found.permissions;
        } else {
            // default subadmin permissions
            userPermissions = currentUser.permissions || { canAddEdit: true, canDelete: false, canManageOrders: true };
        }
    }

    // 2. Display/Hide Super Admin specific items in DOM
    if (isSuper) {
        document.querySelectorAll(".superadmin-only").forEach(el => el.style.display = "block");
        // Show financial statistics card
        elements.adminStatRevenue.parentElement.parentElement.style.display = "flex";
        
        const revenue = orders.reduce((sum, o) => sum + o.total, 0);
        elements.adminStatRevenue.textContent = `${revenue.toLocaleString("fr-FR")} FCFA`;
        
        renderAdminRolesTable();
    } else {
        document.querySelectorAll(".superadmin-only").forEach(el => el.style.display = "none");
        // Hide financial statistics card
        elements.adminStatRevenue.parentElement.parentElement.style.display = "none";
    }

    // Update orders count and product count
    elements.adminStatOrders.textContent = orders.length;
    elements.adminStatProducts.textContent = products.length;
    
    // Update pending badge count
    const pendingOrdersCount = orders.filter(o => !o.status.includes("Livré")).length;
    if (pendingOrdersCount > 0) {
        elements.adminPendingBadge.style.display = "inline-block";
        elements.adminPendingBadge.textContent = pendingOrdersCount;
    } else {
        elements.adminPendingBadge.style.display = "none";
    }
    
    // 3. Render Products Table List
    elements.adminProductsTableBody.innerHTML = "";
    products.forEach(p => {
        const tr = document.createElement("tr");
        const stockInfo = p.stocks ? `S:${p.stocks.S} | M:${p.stocks.M} | L:${p.stocks.L} | XL:${p.stocks.XL}` : "Unique";
        
        // Hide edit/delete actions if not allowed
        let actionButtons = "";
        if (isSuper || userPermissions.canAddEdit) {
            actionButtons += `<button class="btn-icon-only" onclick="editProductInAdmin('${p.id}')" title="Modifier"><i class="fa-solid fa-pen-to-square"></i></button>`;
        }
        if (isSuper || userPermissions.canDelete) {
            actionButtons += `<button class="btn-icon-only btn-delete" onclick="deleteProductFromAdmin('${p.id}')" title="Supprimer"><i class="fa-solid fa-trash-can"></i></button>`;
        }
        
        tr.innerHTML = `
            <td><img src="${escapeHTML(p.image)}" alt="Img" onerror="this.src='https://placehold.co/100x120?text=Logo'"></td>
            <td><strong>${escapeHTML(p.name)}</strong></td>
            <td><span class="badge">${escapeHTML(p.category)}</span></td>
            <td>${p.price.toLocaleString("fr-FR")} F</td>
            <td><code>${stockInfo}</code></td>
            <td>
                <div class="btn-action-group">
                    ${actionButtons || '<span class="text-muted" style="font-size:0.75rem;">Lecture seule</span>'}
                </div>
            </td>
        `;
        elements.adminProductsTableBody.appendChild(tr);
    });

    // Hide/disable Add Product form inputs if subadmin doesn't have add/edit rights
    const saveBtn = document.getElementById("btn-save-product");
    const cancelBtn = document.getElementById("btn-cancel-edit");
    if (!isSuper && !userPermissions.canAddEdit) {
        elements.productAdminForm.querySelectorAll("input, select, textarea, button").forEach(input => {
            input.disabled = true;
        });
        if (saveBtn) saveBtn.textContent = "Accès Restreint (Lecture)";
    } else {
        elements.productAdminForm.querySelectorAll("input, select, textarea, button").forEach(input => {
            input.disabled = false;
        });
        if (saveBtn) saveBtn.textContent = editingProductId ? "Sauvegarder les modifications" : "Créer le produit";
    }
    
    // 4. Render Orders Table List
    elements.adminOrdersTableBody.innerHTML = "";
    if (orders.length === 0) {
        elements.adminOrdersTableBody.innerHTML = `
            <tr>
                <td colspan="8" style="text-align:center; padding: 30px; color: var(--text-muted)">Aucune commande n'a été enregistrée pour le moment.</td>
            </tr>
        `;
    } else {
        orders.forEach(o => {
            const tr = document.createElement("tr");
            let itemsDetailsHtml = o.items.map(it => {
                const displaySize = it.size === "U" ? "" : ` (${it.size})`;
                return `<span style="display:block; font-size:0.75rem;">- ${escapeHTML(it.name)}${displaySize} x${it.qty}</span>`;
            }).join("");
            
            // Order status action dropdown (disable if no right)
            let statusSelect = "";
            if (isSuper || userPermissions.canManageOrders) {
                statusSelect = `
                    <select onchange="updateOrderStatus('${o.id}', this.value)" style="padding: 6px; font-size:0.8rem; border-radius:4px;">
                        <option value="Payée (En attente d'expédition)" ${o.status.includes("Payée") ? "selected" : ""}>Payée</option>
                        <option value="En cours de préparation" ${o.status.includes("préparation") ? "selected" : ""}>Préparation</option>
                        <option value="En cours de livraison" ${o.status.includes("livraison") ? "selected" : ""}>En cours de livraison</option>
                        <option value="Livré et validé" ${o.status.includes("Livré") ? "selected" : ""}>Livré</option>
                    </select>
                `;
            } else {
                statusSelect = `<span class="badge">${escapeHTML(o.status)}</span>`;
            }
            
            tr.innerHTML = `
                <td>
                    <strong>${o.id}</strong><br>
                    <span style="font-size:0.7rem; color:var(--text-muted)">${o.date}</span>
                </td>
                <td>
                    <span style="font-weight:600;">${escapeHTML(o.clientName)}</span><br>
                    <span style="font-size:0.7rem; color:var(--text-muted)">${escapeHTML(o.clientEmail)}</span>
                </td>
                <td>
                    <span>+221 ${escapeHTML(o.clientPhone)}</span><br>
                    <span style="font-size:0.75rem; display:block; max-width:180px; overflow:hidden; text-overflow:ellipsis;">${escapeHTML(o.clientAddress)}</span>
                </td>
                <td>${itemsDetailsHtml}</td>
                <td><strong>${o.total.toLocaleString("fr-FR")} F</strong></td>
                <td>
                    <span class="badge">${escapeHTML(o.paymentMethod)}</span><br>
                    <code style="font-size:0.65rem;">${o.reference}</code>
                </td>
                <td>
                    <span class="badge ${o.status.includes('Livré') ? 'badge-success' : 'badge-accent'}">${escapeHTML(o.status)}</span>
                </td>
                <td>${statusSelect}</td>
            `;
            elements.adminOrdersTableBody.appendChild(tr);
        });
    }
}

function renderAdminRolesTable() {
    const users = JSON.parse(localStorage.getItem("diaw_shoop_users")) || [];
    // Filter out Mamadou Diaw himself from being modified/deleted, but show other admins
    const admins = users.filter(u => u.isAdmin && u.email !== "mamadoudiaw2005@gmail.com");
    
    elements.adminRolesTableBody.innerHTML = "";
    if (admins.length === 0) {
        elements.adminRolesTableBody.innerHTML = `
            <tr>
                <td colspan="4" style="text-align:center; padding: 30px;">Aucun autre administrateur configuré.</td>
            </tr>
        `;
        return;
    }
    
    admins.forEach(admin => {
        const tr = document.createElement("tr");
        
        let roleBadge = "";
        let permissionsHtml = "";
        
        if (admin.isSuperAdmin) {
            roleBadge = `<span class="badge badge-accent">Grand Admin</span>`;
            permissionsHtml = `<span style="font-size:0.8rem; color:var(--text-muted); font-style:italic;">Accès complet (Illimité)</span>`;
        } else {
            roleBadge = `<span class="badge badge-success">Admin Secondaire</span>`;
            const perms = admin.permissions || { canAddEdit: true, canDelete: false, canManageOrders: true };
            permissionsHtml = `
                <div style="display:flex; flex-direction:column; gap:8px;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <label class="switch">
                            <input type="checkbox" ${perms.canAddEdit ? 'checked' : ''} onchange="toggleSubAdminPermission('${admin.email}', 'canAddEdit', this.checked)">
                            <span class="slider round"></span>
                        </label>
                        <span style="font-size:0.75rem;">Ajout/Modif</span>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <label class="switch">
                            <input type="checkbox" ${perms.canDelete ? 'checked' : ''} onchange="toggleSubAdminPermission('${admin.email}', 'canDelete', this.checked)">
                            <span class="slider round"></span>
                        </label>
                        <span style="font-size:0.75rem;">Suppression</span>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <label class="switch">
                            <input type="checkbox" ${perms.canManageOrders ? 'checked' : ''} onchange="toggleSubAdminPermission('${admin.email}', 'canManageOrders', this.checked)">
                            <span class="slider round"></span>
                        </label>
                        <span style="font-size:0.75rem;">Commandes</span>
                    </div>
                </div>
            `;
        }
        
        tr.innerHTML = `
            <td style="padding: 16px 14px; vertical-align: middle; text-align: left;">
                <div style="font-weight:600;">${escapeHTML(admin.name)}</div>
                <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHTML(admin.email)}</div>
            </td>
            <td style="padding: 16px 14px; vertical-align: middle; text-align: left;">
                ${roleBadge}
            </td>
            <td style="padding: 16px 14px; vertical-align: middle; text-align: left;">
                ${permissionsHtml}
            </td>
            <td style="padding: 16px 14px; vertical-align: middle; text-align: left;">
                <button class="btn btn-icon-only btn-delete" onclick="deleteAdminAccount('${admin.email}')" title="Supprimer le compte Admin">
                    <i class="fa-solid fa-trash"></i>
                </button>
            </td>
        `;
        elements.adminRolesTableBody.appendChild(tr);
    });
}

window.toggleSubAdminPermission = function(email, permissionKey, isChecked) {
    const users = JSON.parse(localStorage.getItem("diaw_shoop_users")) || [];
    const admin = users.find(u => u.email === email);
    if (admin) {
        if (!admin.permissions) admin.permissions = {};
        admin.permissions[permissionKey] = isChecked;
        localStorage.setItem("diaw_shoop_users", JSON.stringify(users));
        showToast(`Permission "${permissionKey}" mise à jour pour ${admin.name}.`);
        
        // If current session is this user, update session as well
        if (currentUser && currentUser.email === email) {
            if (!currentUser.permissions) currentUser.permissions = {};
            currentUser.permissions[permissionKey] = isChecked;
            sessionStorage.setItem("diaw_shoop_current_user", JSON.stringify(currentUser));
        }
    }
};

// Update Order status action
window.updateOrderStatus = function(orderId, newStatus) {
    if (!currentUser || !currentUser.isAdmin) return;
    
    const o = orders.find(ord => ord.id === orderId);
    if (o) {
        o.status = newStatus;
        localStorage.setItem("diaw_shoop_orders", JSON.stringify(orders));
        renderAdminDashboard();
        showToast(`Statut de la commande ${orderId} mis à jour : ${newStatus}`);
    }
};

// Edit Product Form Trigger
window.editProductInAdmin = function(productId) {
    if (!currentUser || !currentUser.isAdmin) return;
    
    const prod = products.find(p => p.id === productId);
    if (!prod) return;
    
    editingProductId = productId;
    elements.editProductIdInput.value = productId;
    
    elements.prodNameInput.value = prod.name;
    elements.prodPriceInput.value = prod.price;
    elements.prodCategorySelect.value = prod.category;
    elements.prodDescTextarea.value = prod.description;
    
    // Reset uploader values
    customImageBase64 = "";
    customVideoBase64 = "";
    if (elements.prodImageFileInput) elements.prodImageFileInput.value = "";
    if (elements.prodVideoFileInput) elements.prodVideoFileInput.value = "";
    
    // Check if image is one of presets
    const presetOptions = Array.from(elements.prodImagePresetSelect.options).map(o => o.value);
    const customOptions = document.getElementById("custom-image-options");
    
    if (presetOptions.includes(prod.image)) {
        elements.prodImagePresetSelect.value = prod.image;
        if (customOptions) customOptions.style.display = "none";
        elements.prodImageUrlInput.required = false;
    } else {
        elements.prodImagePresetSelect.value = "custom";
        if (customOptions) customOptions.style.display = "flex";
        if (prod.image && prod.image.startsWith("data:image")) {
            customImageBase64 = prod.image;
            elements.prodImageUrlInput.value = "";
            elements.prodImageUrlInput.required = false;
        } else {
            elements.prodImageUrlInput.value = prod.image || "";
            elements.prodImageUrlInput.required = true;
        }
    }
    
    if (prod.videoUrl && prod.videoUrl.startsWith("data:video")) {
        customVideoBase64 = prod.videoUrl;
        elements.prodVideoInput.value = "";
    } else {
        elements.prodVideoInput.value = prod.videoUrl || "";
    }
    
    // Populate stocks
    if (prod.stocks) {
        document.getElementById("stock-s").value = prod.stocks.S;
        document.getElementById("stock-m").value = prod.stocks.M;
        document.getElementById("stock-l").value = prod.stocks.L;
        document.getElementById("stock-xl").value = prod.stocks.XL;
    }
    
    elements.productFormTitle.textContent = "Modifier l'article";
    elements.btnSaveProduct.textContent = "Sauvegarder les modifications";
    elements.btnCancelEdit.style.display = "block";
    
    // Scroll form into view
    elements.productAdminForm.scrollIntoView({ behavior: "smooth" });
    adjustAdminStockFields();
};

elements.btnCancelEdit.addEventListener("click", () => {
    resetAdminForm();
});

function resetAdminForm() {
    editingProductId = null;
    elements.editProductIdInput.value = "";
    elements.productAdminForm.reset();
    
    const customOptions = document.getElementById("custom-image-options");
    if (customOptions) customOptions.style.display = "none";
    if (elements.prodImageUrlInput) {
        elements.prodImageUrlInput.style.display = "none";
        elements.prodImageUrlInput.required = false;
    }
    
    customImageBase64 = "";
    customVideoBase64 = "";
    if (elements.prodImageFileInput) elements.prodImageFileInput.value = "";
    if (elements.prodVideoFileInput) elements.prodVideoFileInput.value = "";
    
    elements.productFormTitle.textContent = "Ajouter un nouveau produit";
    elements.btnSaveProduct.textContent = "Créer le produit";
    elements.btnCancelEdit.style.display = "none";
    adjustAdminStockFields();
}

// Delete Product Action
window.deleteProductFromAdmin = function(productId) {
    if (!currentUser || !currentUser.isAdmin) return;
    
    if (confirm("Êtes-vous sûr de vouloir supprimer définitivement cet article de la boutique ?")) {
        products = products.filter(p => p.id !== productId);
        localStorage.setItem("diaw_shoop_products", JSON.stringify(products));
        
        // Remove from cart if present
        cart = cart.filter(item => item.id !== productId);
        saveCart();
        renderCart();
        
        // Refresh grids
        renderProductList();
        renderAdminDashboard();
        
        showToast("Article supprimé de la boutique.");
        if (editingProductId === productId) {
            resetAdminForm();
        }
    }
};

// Form submit to Create/Update product
elements.productAdminForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (!currentUser || !currentUser.isAdmin) return;
    
    const name = elements.prodNameInput.value.trim();
    const price = parseInt(elements.prodPriceInput.value);
    const category = elements.prodCategorySelect.value;
    const description = elements.prodDescTextarea.value.trim();
    
    // Resolve image
    let image = elements.prodImagePresetSelect.value;
    if (image === "custom") {
        image = customImageBase64 || elements.prodImageUrlInput.value.trim();
        if (!image) {
            showToast("Veuillez sélectionner un fichier image ou saisir une URL.", "error");
            return;
        }
    }
    
    // Resolve video
    const finalVideoUrl = customVideoBase64 || elements.prodVideoInput.value.trim();
    
    // Sizing Stocks
    const stocks = {
        S: parseInt(document.getElementById("stock-s").value) || 0,
        M: parseInt(document.getElementById("stock-m").value) || 0,
        L: parseInt(document.getElementById("stock-l").value) || 0,
        XL: parseInt(document.getElementById("stock-xl").value) || 0
    };
    
    if (editingProductId) {
        // UPDATE Mode
        const prod = products.find(p => p.id === editingProductId);
        if (prod) {
            prod.name = name;
            prod.price = price;
            prod.category = category;
            prod.description = description;
            prod.image = image;
            prod.videoUrl = finalVideoUrl;
            prod.stocks = stocks;
            
            showToast(`Article "${name}" mis à jour avec succès !`);
        }
    } else {
        // CREATE Mode
        const newId = "prod-" + Math.floor(1000 + Math.random() * 9000);
        const newProd = {
            id: newId,
            name,
            price,
            category,
            description,
            image,
            videoUrl: finalVideoUrl,
            stocks
        };
        products.push(newProd);
        showToast(`Article "${name}" mis en vente avec succès !`);
    }
    
    // Save, refresh tables, reset form
    localStorage.setItem("diaw_shoop_products", JSON.stringify(products));
    renderProductList();
    renderAdminDashboard();
    resetAdminForm();
});

// Dynamic Store Settings management
function applyStoreSettings() {
    const settings = JSON.parse(localStorage.getItem("diaw_shoop_settings")) || {
        whatsapp: "221785946427",
        email: "mamadoudiaw2005@gmail.com",
        address: "Liberté 6 Extension, Dakar, Sénégal",
        hours: "Lun - Ven : 10h - 22h / Sam : 10h - 18h",
        instagram: "https://instagram.com/",
        facebook: "https://facebook.com/",
        tiktok: "https://tiktok.com/",
        googleClientId: "845239922097-n8l4g8i4e2j99p0lhq1f3c30r7o0p61i.apps.googleusercontent.com",
        shopName: "DIAW SHOOP",
        shopLogo: "assets/logo_diaw_shoop.jpg",
        payoutNumber: "770000000",
        payoutCarrier: "wave"
    };
    
    // Update logo name and image across the site
    const logoName = settings.shopName || "DIAW SHOOP";
    const logoImgUrl = settings.shopLogo || "assets/logo_diaw_shoop.jpg";
    
    // Header Logo
    const logoHeaderImg = document.getElementById("logo-header-img");
    if (logoHeaderImg) logoHeaderImg.src = logoImgUrl;
    
    const logoHeaderSub = document.getElementById("logo-header-text");
    if (logoHeaderSub) {
        if (logoName.toUpperCase().startsWith("DIAW")) {
            logoHeaderSub.innerHTML = `<span style="color: var(--accent);">DIAW</span>${logoName.substring(4)}`;
        } else {
            logoHeaderSub.textContent = logoName;
        }
    }
    
    // Portal Logo
    const logoPortalImg = document.getElementById("logo-portal-img");
    if (logoPortalImg) logoPortalImg.src = logoImgUrl;
    
    const logoPortalText = document.getElementById("logo-portal-text");
    if (logoPortalText) logoPortalText.textContent = logoName;
    
    // Footer Logo
    const logoFooterImg = document.getElementById("logo-footer-img");
    if (logoFooterImg) logoFooterImg.src = logoImgUrl;
    
    const logoFooterText = document.getElementById("logo-footer-text");
    if (logoFooterText) {
        if (logoName.toUpperCase().startsWith("DIAW")) {
            logoFooterText.innerHTML = `<span style="color: var(--accent);">DIAW</span>${logoName.substring(4)}`;
        } else {
            logoFooterText.textContent = logoName;
        }
    }
    
    // Overwrite footer DOM references
    const footerPhone = document.getElementById("footer-phone-display");
    const footerAddress = document.getElementById("footer-address-display");
    const footerEmail = document.getElementById("footer-email-display");
    const footerHours = document.getElementById("footer-hours-display");
    const footerWaLink = document.getElementById("footer-link-whatsapp-icon");
    const footerIgLink = document.getElementById("footer-link-instagram");
    const footerFbLink = document.getElementById("footer-link-facebook");
    const footerTtLink = document.getElementById("footer-link-tiktok");
    
    if (footerPhone) footerPhone.textContent = `+221 ${settings.whatsapp.replace("221", "")}`;
    if (footerAddress) footerAddress.textContent = settings.address;
    if (footerEmail) footerEmail.textContent = settings.email;
    if (footerHours) footerHours.textContent = settings.hours;
    if (footerWaLink) footerWaLink.href = `https://wa.me/${settings.whatsapp}`;
    if (footerIgLink) footerIgLink.href = settings.instagram || "https://instagram.com/";
    if (footerFbLink) footerFbLink.href = settings.facebook || "https://facebook.com/";
    if (footerTtLink) footerTtLink.href = settings.tiktok || "https://tiktok.com/";
    
    // Update settings form input values
    const settingsWhatsappInput = document.getElementById("settings-whatsapp");
    const settingsEmailInput = document.getElementById("settings-email");
    const settingsAddressInput = document.getElementById("settings-address");
    const settingsHoursInput = document.getElementById("settings-hours");
    const settingsInstagramInput = document.getElementById("settings-instagram");
    const settingsFacebookInput = document.getElementById("settings-facebook");
    const settingsTiktokInput = document.getElementById("settings-tiktok");
    const settingsGoogleClientIdInput = document.getElementById("settings-google-client-id");
    const settingsShopNameInput = document.getElementById("settings-shop-name");
    const settingsShopLogoSelect = document.getElementById("settings-shop-logo-select");
    const settingsPayoutNumberInput = document.getElementById("settings-payout-number");
    const settingsPayoutCarrierInput = document.getElementById("settings-payout-carrier");
    
    if (settingsWhatsappInput) settingsWhatsappInput.value = settings.whatsapp;
    if (settingsEmailInput) settingsEmailInput.value = settings.email;
    if (settingsAddressInput) settingsAddressInput.value = settings.address;
    if (settingsHoursInput) settingsHoursInput.value = settings.hours || "Lun - Ven : 10h - 22h / Sam : 10h - 18h";
    if (settingsInstagramInput) settingsInstagramInput.value = settings.instagram || "";
    if (settingsFacebookInput) settingsFacebookInput.value = settings.facebook || "";
    if (settingsTiktokInput) settingsTiktokInput.value = settings.tiktok || "";
    if (settingsGoogleClientIdInput) settingsGoogleClientIdInput.value = settings.googleClientId || "";
    if (settingsShopNameInput) settingsShopNameInput.value = settings.shopName || "DIAW SHOOP";
    if (settingsPayoutNumberInput) settingsPayoutNumberInput.value = settings.payoutNumber || "770000000";
    if (settingsPayoutCarrierInput) settingsPayoutCarrierInput.value = settings.payoutCarrier || "wave";
    if (settingsShopLogoSelect) {
        settingsShopLogoSelect.value = settings.shopLogo && settings.shopLogo.startsWith("data:") ? "custom" : "preset";
        const fileWrapper = document.getElementById("settings-shop-logo-file-wrapper");
        if (fileWrapper) {
            fileWrapper.style.display = settingsShopLogoSelect.value === "custom" ? "block" : "none";
        }
    }
}

const shopSettingsForm = document.getElementById("shop-settings-form");
if (shopSettingsForm) {
    shopSettingsForm.addEventListener("submit", (e) => {
        e.preventDefault();
        
        if (!currentUser || !currentUser.isSuperAdmin) {
            showToast("Accès non autorisé.", "error");
            return;
        }
        
        const currentSettings = JSON.parse(localStorage.getItem("diaw_shoop_settings")) || {};
        
        const whatsapp = document.getElementById("settings-whatsapp").value.trim().replace(/\+/g, '').replace(/\s+/g, '');
        const email = document.getElementById("settings-email").value.trim();
        const address = document.getElementById("settings-address").value.trim();
        const hours = document.getElementById("settings-hours").value.trim();
        const instagram = document.getElementById("settings-instagram").value.trim() || "https://instagram.com/";
        const facebook = document.getElementById("settings-facebook").value.trim() || "https://facebook.com/";
        const tiktok = document.getElementById("settings-tiktok").value.trim() || "https://tiktok.com/";
        const googleClientId = document.getElementById("settings-google-client-id").value.trim() || "845239922097-n8l4g8i4e2j99p0lhq1f3c30r7o0p61i.apps.googleusercontent.com";
        const shopName = document.getElementById("settings-shop-name").value.trim() || "DIAW SHOOP";
        const payoutNumber = document.getElementById("settings-payout-number").value.trim() || "770000000";
        const payoutCarrier = document.getElementById("settings-payout-carrier").value || "wave";
        
        const logoSelect = document.getElementById("settings-shop-logo-select").value;
        let shopLogo = "assets/logo_diaw_shoop.jpg";
        if (logoSelect === "custom") {
            shopLogo = customLogoBase64 || currentSettings.shopLogo || "assets/logo_diaw_shoop.jpg";
        }
        
        const newSettings = { whatsapp, email, address, hours, instagram, facebook, tiktok, googleClientId, shopName, shopLogo, payoutNumber, payoutCarrier };
        localStorage.setItem("diaw_shoop_settings", JSON.stringify(newSettings));
        
        applyStoreSettings();
        // Re-initialize Google Sign-in with the new Client ID
        if (typeof initializeGoogleSignIn === "function") {
            initializeGoogleSignIn();
        }
        showToast("Configuration de la boutique enregistrée avec succès !");
    });
}

// --- 12. LOGO PORTAL INTERMEDIARY NAVIGATION ---
const brandLogo = document.getElementById("brand-logo");
const portalOverlay = document.getElementById("logo-portal-overlay");
const btnClosePortal = document.getElementById("btn-close-portal");

if (brandLogo && portalOverlay) {
    brandLogo.addEventListener("click", (e) => {
        e.preventDefault();
        portalOverlay.style.display = "flex";
        setTimeout(() => portalOverlay.classList.add("open"), 10);
    });
}

const closePortal = () => {
    if (portalOverlay) {
        portalOverlay.classList.remove("open");
        setTimeout(() => portalOverlay.style.display = "none", 300);
    }
};

if (btnClosePortal) {
    btnClosePortal.addEventListener("click", closePortal);
}

// Nav buttons in portal
const portalBtnHome = document.getElementById("portal-btn-home");
const portalBtnShop = document.getElementById("portal-btn-shop");
const portalBtnContact = document.getElementById("portal-btn-contact");

const scrollToTarget = (targetId) => {
    closePortal();
    
    // Force close admin if currently open
    const adminSectionEl = document.getElementById("admin-section");
    if (adminSectionEl && adminSectionEl.style.display === "block" && elements.btnCloseAdmin) {
        elements.btnCloseAdmin.click();
    }
    
    setTimeout(() => {
        const el = document.getElementById(targetId) || document.querySelector(targetId);
        if (el) {
            el.scrollIntoView({ behavior: "smooth" });
        }
    }, 350); // Wait for portal close animation
};

if (portalBtnHome) {
    portalBtnHome.addEventListener("click", () => scrollToTarget("main-header"));
}
if (portalBtnShop) {
    portalBtnShop.addEventListener("click", () => scrollToTarget("shop-section"));
}
if (portalBtnContact) {
    portalBtnContact.addEventListener("click", () => scrollToTarget(".main-footer"));
}

// --- 13. REAL GOOGLE OAUTH 2.0 INTEGRATION ---
function decodeJwtResponse(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
}

function handleGoogleCredentialResponse(response) {
    try {
        const payload = decodeJwtResponse(response.credential);
        const email = payload.email.toLowerCase();
        const name = payload.name;
        const avatar = payload.picture;
        
        const users = JSON.parse(localStorage.getItem("diaw_shoop_users")) || [];
        let user = users.find(u => u.email === email);
        
        if (!user) {
            // Register a new Client user dynamically on real Google Login
            user = {
                email,
                name,
                passwordHash: mockHashPassword("google123"),
                isAdmin: false,
                isSuperAdmin: false,
                avatar: avatar
            };
            users.push(user);
            localStorage.setItem("diaw_shoop_users", JSON.stringify(users));
        } else {
            // Update avatar image from Google
            user.avatar = avatar;
            localStorage.setItem("diaw_shoop_users", JSON.stringify(users));
        }
        
        sessionStorage.setItem("diaw_shoop_current_user", JSON.stringify(user));
        currentUser = user;
        updateUserUI();
        
        elements.authModal.classList.remove("open");
        showToast(`Connecté via Google : Bienvenue ${currentUser.name} !`);
    } catch (err) {
        console.error("Google Authentication error:", err);
        showToast("Erreur d'authentification avec votre compte Google.", "error");
    }
}

function initializeGoogleSignIn() {
    if (typeof google === 'undefined') {
        setTimeout(initializeGoogleSignIn, 300);
        return;
    }
    
    const settings = JSON.parse(localStorage.getItem("diaw_shoop_settings")) || {};
    const clientId = settings.googleClientId || "845239922097-n8l4g8i4e2j99p0lhq1f3c30r7o0p61i.apps.googleusercontent.com";
    
    google.accounts.id.initialize({
        client_id: clientId,
        callback: handleGoogleCredentialResponse,
        auto_select: false
    });
    
    const btnContainer = document.getElementById("google-signin-btn-container");
    if (btnContainer) {
        btnContainer.innerHTML = ""; // Clear
        google.accounts.id.renderButton(
            btnContainer,
            { 
                theme: "outline", 
                size: "large", 
                width: "280", 
                text: "continue_with",
                shape: "rectangular",
                logo_alignment: "left"
            }
        );
    }
}

// Initialize Google Sign-in on Startup
setTimeout(initializeGoogleSignIn, 500);

// --- 14. DYNAMIC LOGO & ADMIN MANAGEMENT ACTIONS ---
let customLogoBase64 = "";
const settingsShopLogoSelect = document.getElementById("settings-shop-logo-select");
const settingsShopLogoFileWrapper = document.getElementById("settings-shop-logo-file-wrapper");
const settingsShopLogoFile = document.getElementById("settings-shop-logo-file");

if (settingsShopLogoSelect && settingsShopLogoFileWrapper) {
    settingsShopLogoSelect.addEventListener("change", function() {
        if (this.value === "custom") {
            settingsShopLogoFileWrapper.style.display = "block";
        } else {
            settingsShopLogoFileWrapper.style.display = "none";
            customLogoBase64 = "";
        }
    });
}

if (settingsShopLogoFile) {
    settingsShopLogoFile.addEventListener("change", function(e) {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(evt) {
                customLogoBase64 = evt.target.result;
            };
            reader.readAsDataURL(file);
        }
    });
}

// Add Admin Form Submission Handler
const addAdminForm = document.getElementById("add-admin-form");
if (addAdminForm) {
    addAdminForm.addEventListener("submit", (e) => {
        e.preventDefault();
        
        if (!currentUser || !currentUser.isSuperAdmin) {
            showToast("Accès non autorisé.", "error");
            return;
        }
        
        const name = document.getElementById("new-admin-name").value.trim();
        const email = document.getElementById("new-admin-email").value.trim().toLowerCase();
        const password = document.getElementById("new-admin-password").value;
        const role = document.getElementById("new-admin-role-select").value;
        
        if (!name || !email || !password) {
            showToast("Veuillez remplir tous les champs.", "error");
            return;
        }
        
        const users = JSON.parse(localStorage.getItem("diaw_shoop_users")) || [];
        if (users.some(u => u.email === email)) {
            showToast("Un utilisateur avec cet email existe déjà.", "error");
            return;
        }
        
        const isSuper = role === "superadmin";
        
        const newAdmin = {
            email,
            name,
            passwordHash: mockHashPassword(password),
            isAdmin: true,
            isSuperAdmin: isSuper,
            avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(name)}`,
            permissions: isSuper ? {
                canAddEdit: true,
                canDelete: true,
                canManageOrders: true
            } : {
                canAddEdit: true,
                canDelete: false,
                canManageOrders: true
            }
        };
        
        users.push(newAdmin);
        localStorage.setItem("diaw_shoop_users", JSON.stringify(users));
        showToast(`Le compte Administrateur pour ${name} a été créé avec succès !`);
        
        // Clear fields
        document.getElementById("new-admin-name").value = "";
        document.getElementById("new-admin-email").value = "";
        document.getElementById("new-admin-password").value = "";
        
        renderAdminRolesTable();
    });
}

// Global window action to delete admin
window.deleteAdminAccount = function(email) {
    if (!currentUser || !currentUser.isSuperAdmin) {
        showToast("Seul le Grand Administrateur peut supprimer des comptes.", "error");
        return;
    }
    
    if (email === "mamadoudiaw2005@gmail.com") {
        showToast("Vous ne pouvez pas supprimer le compte racine de Mamadou Diaw.", "error");
        return;
    }
    
    if (confirm(`Êtes-vous sûr de vouloir supprimer définitivement le compte admin "${email}" ?`)) {
        let users = JSON.parse(localStorage.getItem("diaw_shoop_users")) || [];
        users = users.filter(u => u.email !== email);
        localStorage.setItem("diaw_shoop_users", JSON.stringify(users));
        showToast("Compte administrateur supprimé avec succès.");
        renderAdminRolesTable();
    }
};

// --- 15. CUSTOMER REVIEWS & RATINGS SYSTEM ---
function renderProductReviews(productId) {
    const prodReviews = reviews.filter(r => r.productId === productId);
    const count = prodReviews.length;
    
    const countEl = document.getElementById("modal-reviews-count");
    const avgEl = document.getElementById("modal-reviews-avg");
    const listEl = document.getElementById("modal-reviews-list");
    
    if (countEl) countEl.textContent = count;
    
    if (avgEl) {
        if (count > 0) {
            const avg = prodReviews.reduce((sum, r) => sum + r.rating, 0) / count;
            avgEl.innerHTML = `${avg.toFixed(1)} <i class="fa-solid fa-star"></i>`;
            avgEl.style.display = "inline-block";
        } else {
            avgEl.innerHTML = `0.0 <i class="fa-solid fa-star"></i>`;
        }
    }
    
    if (listEl) {
        listEl.innerHTML = "";
        if (count === 0) {
            listEl.innerHTML = `<p style="font-size:0.8rem; color:var(--text-muted); font-style:italic; padding: 10px 0;">Aucun avis pour le moment. Soyez le premier à donner votre avis !</p>`;
        } else {
            // Sort reviews by date descending
            const sortedReviews = [...prodReviews].sort((a, b) => new Date(b.date) - new Date(a.date));
            sortedReviews.forEach(r => {
                const dateFormatted = new Date(r.date).toLocaleDateString("fr-FR", {
                    day: "numeric",
                    month: "long",
                    year: "numeric"
                });
                
                const starsHtml = Array.from({ length: 5 }, (_, i) => {
                    return `<i class="${i < r.rating ? 'fa-solid' : 'fa-regular'} fa-star"></i>`;
                }).join('');
                
                const div = document.createElement("div");
                div.className = "review-item";
                div.innerHTML = `
                    <div class="review-item-header">
                        <div class="review-item-author">
                            <img src="${r.avatar || 'https://api.dicebear.com/7.x/initials/svg?seed=' + encodeURIComponent(r.author)}" class="review-item-avatar" alt="Avatar">
                            <span class="review-item-name">${escapeHTML(r.author)}</span>
                        </div>
                        <div class="review-item-stars">${starsHtml}</div>
                    </div>
                    <div style="display:flex; justify-content:space-between; margin-bottom:5px;">
                        <span class="review-item-date">Le ${dateFormatted}</span>
                    </div>
                    <p class="review-item-text">${escapeHTML(r.text)}</p>
                `;
                listEl.appendChild(div);
            });
        }
    }
    
    // Auto fill form name
    const reviewAuthorInput = document.getElementById("review-author-name");
    if (reviewAuthorInput) {
        reviewAuthorInput.value = currentUser ? currentUser.name : "";
    }
    
    // Reset star selector to 5 active
    const starSelectorContainer = document.getElementById("star-rating-selector");
    if (starSelectorContainer) {
        const stars = starSelectorContainer.querySelectorAll(".star-select");
        stars.forEach(s => s.classList.add("active"));
    }
    const ratingVal = document.getElementById("review-rating-value");
    if (ratingVal) ratingVal.value = "5";
}

// Stars rating selector interactivity
const starSelectorContainer = document.getElementById("star-rating-selector");
if (starSelectorContainer) {
    starSelectorContainer.addEventListener("click", (e) => {
        const star = e.target.closest(".star-select");
        if (!star) return;
        
        const rating = parseInt(star.getAttribute("data-rating"));
        const ratingVal = document.getElementById("review-rating-value");
        if (ratingVal) ratingVal.value = rating;
        
        const stars = starSelectorContainer.querySelectorAll(".star-select");
        stars.forEach(s => {
            const r = parseInt(s.getAttribute("data-rating"));
            if (r <= rating) {
                s.classList.add("active");
            } else {
                s.classList.remove("active");
            }
        });
    });
}

// Add Review form submit handler
const addReviewForm = document.getElementById("add-review-form");
if (addReviewForm) {
    addReviewForm.addEventListener("submit", (e) => {
        e.preventDefault();
        
        if (!currentDetailProduct) {
            showToast("Une erreur est survenue lors de la sélection du produit.", "error");
            return;
        }
        
        const author = document.getElementById("review-author-name").value.trim();
        const text = document.getElementById("review-text-content").value.trim();
        const rating = parseInt(document.getElementById("review-rating-value").value) || 5;
        
        if (!author || !text) {
            showToast("Veuillez remplir tous les champs du commentaire.", "error");
            return;
        }
        
        const newReview = {
            id: "rev-" + Date.now(),
            productId: currentDetailProduct.id,
            author: author,
            rating: rating,
            text: text,
            date: new Date().toISOString(),
            avatar: currentUser ? currentUser.avatar : `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(author)}`
        };
        
        reviews.push(newReview);
        localStorage.setItem("diaw_shoop_reviews", JSON.stringify(reviews));
        
        showToast("Votre avis a été publié avec succès ! Merci de votre retour.");
        
        // Clear text field
        document.getElementById("review-text-content").value = "";
        
        // Refresh reviews and catalog views
        renderProductReviews(currentDetailProduct.id);
        renderProductList();
    });
}

// Dynamic adjustment of stock fields based on product category in admin form
const prodCategoryInput = document.getElementById("prod-category");
function adjustAdminStockFields() {
    if (!prodCategoryInput) return;
    
    const cat = prodCategoryInput.value;
    const isClothing = cat === "vetements" || cat === "robes";
    
    const sectionLabel = document.getElementById("admin-stock-section-label");
    const spanS = document.getElementById("stock-span-s");
    const fieldM = document.getElementById("stock-field-m");
    const fieldL = document.getElementById("stock-field-l");
    const fieldXL = document.getElementById("stock-field-xl");
    
    if (isClothing) {
        if (sectionLabel) sectionLabel.textContent = "Stocks Disponibles par Taille (Vêtements uniquement)";
        if (spanS) spanS.textContent = "S";
        if (fieldM) fieldM.style.display = "flex";
        if (fieldL) fieldL.style.display = "flex";
        if (fieldXL) fieldXL.style.display = "flex";
    } else {
        if (sectionLabel) sectionLabel.textContent = "Quantité Totale en Stock (Produit Unique)";
        if (spanS) spanS.textContent = "Quantité en stock";
        if (fieldM) fieldM.style.display = "none";
        if (fieldL) fieldL.style.display = "none";
        if (fieldXL) fieldXL.style.display = "none";
    }
}

if (prodCategoryInput) {
    prodCategoryInput.addEventListener("change", adjustAdminStockFields);
}

// Initial call
setTimeout(adjustAdminStockFields, 600);


