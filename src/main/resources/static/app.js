(function () {
    'use strict';

    // --- API base is same-origin since served by Spring Boot ---
    var API_BASE = '/api/v1';

    var baselineToken = '';
    var currentToken = '';       // active JWT (populated from login response or /auth/token)

    var VIEWS = ['view-login', 'view-register', 'view-dashboard'];

    // --- Login view ---
    var loginForm = document.getElementById('loginForm');
    var loginUsername = document.getElementById('loginUsername');
    var loginPassword = document.getElementById('loginPassword');
    var loginSubmitBtn = document.getElementById('loginSubmitBtn');
    var loginStatus = document.getElementById('loginStatus');
    var goRegisterLink = document.getElementById('goRegisterLink');

    // --- Register view ---
    var registerForm = document.getElementById('registerForm');
    var registerUsername = document.getElementById('registerUsername');
    var registerEmail = document.getElementById('registerEmail');
    var registerPassword = document.getElementById('registerPassword');
    var registerSubmitBtn = document.getElementById('registerSubmitBtn');
    var registerStatus = document.getElementById('registerStatus');
    var goLoginLink = document.getElementById('goLoginLink');

    // --- Dashboard view ---
    var dashboardUser = document.getElementById('dashboardUser');
    var signOutBtn = document.getElementById('signOutBtn');
    var generateBtn = document.getElementById('generateBtn');
    var generatedToken = document.getElementById('generatedToken');
    var tokenInput = document.getElementById('tokenInput');
    var injectNoneBtn = document.getElementById('injectNoneBtn');
    var verifyBtn = document.getElementById('verifyBtn');
    var terminal = document.getElementById('terminal');

    // --- Orders ---
    var orderForm = document.getElementById('orderForm');
    var orderItem = document.getElementById('orderItem');
    var orderQuantity = document.getElementById('orderQuantity');
    var orderSubmitBtn = document.getElementById('orderSubmitBtn');
    var orderStatus = document.getElementById('orderStatus');
    var ordersTableBody = document.getElementById('ordersTableBody');

    var TERMINAL_BASE =
        'px-4 py-4 text-sm font-mono leading-relaxed min-h-[88px] whitespace-pre-wrap bg-black transition-colors duration-200';

    // ================================================================
    //  VIEW SWITCHING
    // ================================================================

    function showView(viewId) {
        VIEWS.forEach(function (id) {
            document.getElementById(id).classList.add('hidden');
        });
        document.getElementById(viewId).classList.remove('hidden');
    }

    // ================================================================
    //  STATUS HELPERS
    // ================================================================

    function showStatus(element, message) {
        element.textContent = message;
        element.classList.remove('hidden');
    }

    function hideStatus(element) {
        element.classList.add('hidden');
        element.textContent = '';
    }

    // ================================================================
    //  TERMINAL
    // ================================================================

    function setTerminal(message, tone) {
        terminal.textContent = message;
        if (tone === 'ok') {
            terminal.className = TERMINAL_BASE + ' text-[#e5e5e5]';
        } else if (tone === 'blocked') {
            terminal.className = TERMINAL_BASE + ' text-[#dc2626]';
        } else {
            terminal.className = TERMINAL_BASE + ' text-[#737373]';
        }
    }

    // ================================================================
    //  LOADING / BUTTON STATE
    // ================================================================

    function setButtonLoading(btn, isLoading, originalText) {
        btn.disabled = isLoading;
        if (isLoading) {
            btn._originalText = btn.textContent;
            btn.innerHTML = '<span class="spinner"></span>' + originalText;
        } else {
            btn.textContent = btn._originalText || originalText;
        }
    }

    // ================================================================
    //  TOKEN MANAGEMENT  (cookie handles auth; currentToken for lab display)
    // ================================================================

    function populateLab(token) {
        baselineToken = token;
        generatedToken.textContent = token;
        tokenInput.value = token;
        updateLabControls(true);
    }

    function updateLabControls(hasToken) {
        verifyBtn.disabled = !hasToken;
        injectNoneBtn.disabled = !hasToken;
    }

    function clearTokenSurfaces() {
        baselineToken = '';
        currentToken = '';
        generatedToken.textContent = '';
        tokenInput.value = '';
        updateLabControls(false);
        setTerminal('Awaiting token verification.', 'idle');
    }

    function resetDashboard() {
        clearTokenSurfaces();
        clearOrdersTable();
    }

    function enterDashboard(username, token) {
        dashboardUser.textContent = 'Signed in as ' + username;
        clearTokenSurfaces();
        showView('view-dashboard');

        if (token) {
            currentToken = token;
            populateLab(token);
            setTerminal('Authenticated. Token ready in lab below.', 'ok');
        }

        fetchUserProfile();
        fetchOrders();
    }

    // ================================================================
    //  API HELPERS
    // ================================================================

    function extractErrorMessage(body, fallback) {
        if (!body) return fallback;
        if (typeof body === 'string') return body;
        if (body.error && typeof body.error === 'string') return body.error;
        if (body.message) return body.message;
        return fallback;
    }

    async function apiRequest(path, options) {
        var headers = { 'Content-Type': 'application/json' };
        if (options.headers) {
            Object.keys(options.headers).forEach(function (key) {
                headers[key] = options.headers[key];
            });
        }

        var response = await fetch(API_BASE + path, {
            method: options.method || 'GET',
            headers: headers,
            body: options.body,
            credentials: 'include'
        });

        var text = await response.text();
        var body = null;
        if (text) {
            try { body = JSON.parse(text); } catch (e) { body = text; }
        }
        return { response: response, body: body };
    }

    async function fetchAccessToken(username, password) {
        var result = await apiRequest('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username: username, password: password })
        });

        if (result.response.ok && result.body && result.body.accessToken) {
            return result.body.accessToken;
        }

        throw new Error(extractErrorMessage(result.body, 'Authentication failed.'));
    }

    // ================================================================
    //  JWT INJECTION UTILS
    // ================================================================

    function base64UrlEncode(str) {
        var bytes = new TextEncoder().encode(str);
        var binary = '';
        bytes.forEach(function (b) { binary += String.fromCharCode(b); });
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function decodeJwtSegment(token, index) {
        var part = token.split('.')[index];
        var padded = part.replace(/-/g, '+').replace(/_/g, '/');
        return atob(padded);
    }

    function buildAlgNoneToken(originalToken) {
        var parts = originalToken.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT structure. Paste a valid token into the lab first.');
        }

        var header = JSON.parse(decodeJwtSegment(originalToken, 0));
        header.alg = 'none';

        var newHeader = base64UrlEncode(JSON.stringify(header));
        return newHeader + '.' + parts[1] + '.';
    }

    // ================================================================
    //  USER PROFILE
    // ================================================================

    async function fetchUserProfile() {
        if (!currentToken) return;
        try {
            var result = await apiRequest('/users/me', {
                method: 'GET',
                headers: { 'Authorization': 'Bearer ' + currentToken }
            });
            if (result.response.ok && result.body) {
                var roles = (result.body.roles || []).join(', ');
                dashboardUser.textContent = 'Signed in as ' + result.body.userId + (roles ? ' [' + roles + ']' : '');
            }
        } catch (e) { /* non-critical */ }
    }

    // ================================================================
    //  ORDERS CRUD
    // ================================================================

    function clearOrdersTable() {
        ordersTableBody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-[#525252]">No orders yet. Create one above.</td></tr>';
    }

    async function fetchOrders() {
        if (!currentToken) return;
        try {
            var result = await apiRequest('/orders', {
                method: 'GET',
                headers: { 'Authorization': 'Bearer ' + currentToken }
            });
            if (result.response.ok && Array.isArray(result.body)) {
                renderOrders(result.body);
            }
        } catch (e) { /* orders unavailable */ }
    }

    function renderOrders(orders) {
        if (!orders || orders.length === 0) {
            clearOrdersTable();
            return;
        }
        ordersTableBody.innerHTML = orders.map(function (o) {
            var shortId = (o.orderId || '').substring(0, 8);
            var statusClass = o.status === 'CREATED'
                ? 'text-[#e5e5e5]'
                : 'text-[#737373]';
            return (
                '<tr class="border-b border-[#111111] hover:bg-[#0a0a0a] transition-colors">' +
                '<td class="py-2.5 pr-3 font-mono text-[#525252]">' + escapeHtml(shortId) + '...</td>' +
                '<td class="py-2.5 pr-3 text-[#e5e5e5]">' + escapeHtml(o.item || '-') + '</td>' +
                '<td class="py-2.5 pr-3">' + (o.quantity || 0) + '</td>' +
                '<td class="py-2.5 pr-3 ' + statusClass + '">' + escapeHtml(o.status || '-') + '</td>' +
                '<td class="py-2.5">' +
                '<button class="text-[#525252] hover:text-[#dc2626] transition-colors text-[10px] uppercase tracking-wider" ' +
                'data-order-id="' + escapeHtml(o.orderId) + '">Del</button>' +
                '</td>' +
                '</tr>'
            );
        }).join('');

        // Attach delete handlers
        ordersTableBody.querySelectorAll('button[data-order-id]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                deleteOrder(btn.getAttribute('data-order-id'));
            });
        });
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    async function deleteOrder(orderId) {
        if (!currentToken) return;
        try {
            var result = await apiRequest('/orders/' + encodeURIComponent(orderId), {
                method: 'DELETE',
                headers: { 'Authorization': 'Bearer ' + currentToken }
            });
            if (result.response.ok) {
                setTerminal('Order ' + orderId.substring(0, 8) + '... deleted.', 'ok');
                fetchOrders();
            } else {
                setTerminal('Delete failed: ' + extractErrorMessage(result.body, 'Forbidden'), 'blocked');
            }
        } catch (e) {
            setTerminal('Delete error: ' + e.message, 'blocked');
        }
    }

    // ================================================================
    //  EVENT: Navigate to Register
    // ================================================================

    goRegisterLink.addEventListener('click', function () {
        hideStatus(loginStatus);
        showView('view-register');
    });

    goLoginLink.addEventListener('click', function () {
        hideStatus(registerStatus);
        showView('view-login');
    });

    // ================================================================
    //  EVENT: Register
    // ================================================================

    registerForm.addEventListener('submit', async function (event) {
        event.preventDefault();
        var username = registerUsername.value.trim();
        var email = registerEmail.value.trim();
        var password = registerPassword.value;

        if (!username || !email || !password) {
            showStatus(registerStatus, 'All fields are required.');
            return;
        }
        if (password.length < 3) {
            showStatus(registerStatus, 'Password must be at least 3 characters.');
            return;
        }

        setButtonLoading(registerSubmitBtn, true, 'Creating...');

        try {
            var result = await apiRequest('/auth/register', {
                method: 'POST',
                body: JSON.stringify({
                    username: username,
                    email: email,
                    password: password,
                    role: 'ROLE_USER'
                })
            });

            if (result.response.ok) {
                registerForm.reset();
                hideStatus(registerStatus);
                showView('view-login');
                showStatus(loginStatus, 'Account created. Sign in to continue.');
            } else {
                showStatus(registerStatus, extractErrorMessage(result.body, 'Registration failed.'));
            }
        } catch (error) {
            showStatus(registerStatus, 'Network error: ' + error.message);
        } finally {
            setButtonLoading(registerSubmitBtn, false, 'Create Account');
        }
    });

    // ================================================================
    //  EVENT: Login
    // ================================================================

    loginForm.addEventListener('submit', async function (event) {
        event.preventDefault();
        var username = loginUsername.value.trim();
        var password = loginPassword.value;

        if (!username || !password) {
            showStatus(loginStatus, 'Username and password required.');
            return;
        }

        setButtonLoading(loginSubmitBtn, true, 'Signing in...');

        try {
            var token = await fetchAccessToken(username, password);
            loginForm.reset();
            hideStatus(loginStatus);
            enterDashboard(username, token);
        } catch (error) {
            showStatus(loginStatus, error.message);
        } finally {
            setButtonLoading(loginSubmitBtn, false, 'Sign In');
        }
    });

    // ================================================================
    //  EVENT: Sign Out (calls server to revoke token)
    // ================================================================

    signOutBtn.addEventListener('click', async function () {
        try {
            await apiRequest('/auth/logout', { method: 'POST' });
        } catch (e) { /* best-effort */ }
        resetDashboard();
        showView('view-login');
    });

    // ================================================================
    //  EVENT: Generate Token
    // ================================================================

    generateBtn.addEventListener('click', async function () {
        setButtonLoading(generateBtn, true, 'Generating...');

        try {
            var result = await apiRequest('/auth/token', { method: 'GET' });
            if (result.response.ok && result.body && result.body.accessToken) {
                currentToken = result.body.accessToken;
                populateLab(currentToken);
                setTerminal('Token issued and loaded into lab. Ready to verify or inject.', 'ok');
            } else {
                setTerminal('Session expired. Sign in again.', 'idle');
                showView('view-login');
            }
        } catch (error) {
            setTerminal('Session expired. Sign in again.', 'blocked');
            showView('view-login');
        } finally {
            setButtonLoading(generateBtn, false, 'Generate Token');
        }
    });

    // ================================================================
    //  EVENT: Inject alg=none
    // ================================================================

    injectNoneBtn.addEventListener('click', function () {
        var token = tokenInput.value.trim();
        if (!token) {
            setTerminal('No token available to inject.', 'idle');
            return;
        }

        try {
            var attackToken = buildAlgNoneToken(token);
            tokenInput.value = attackToken;
            updateLabControls(true);
            setTerminal('alg=none payload injected into textarea. Route token to test proactive filter.', 'idle');
        } catch (error) {
            setTerminal(error.message, 'blocked');
        }
    });

    // ================================================================
    //  EVENT: Verify & Route Token
    // ================================================================

    verifyBtn.addEventListener('click', async function () {
        var token = tokenInput.value.trim();
        if (!token) {
            setTerminal('No token to route.', 'idle');
            return;
        }

        var isModified = baselineToken === '' || token !== baselineToken;

        setButtonLoading(verifyBtn, true, 'Verifying...');

        try {
            var result = await apiRequest('/secure/data', {
                method: 'GET',
                headers: { Authorization: 'Bearer ' + token }
            });

            if (!isModified && result.response.status === 200) {
                setTerminal('Status 200 OK: Valid RSA Signature. Access Granted.', 'ok');
                return;
            }

            if (isModified || result.response.status === 401) {
                setTerminal('Status 401 Unauthorized: Proactive Filter Blocked Payload.', 'blocked');
                return;
            }

            setTerminal(
                'Status ' + result.response.status + ': ' + extractErrorMessage(result.body, 'Request rejected.'),
                'blocked'
            );
        } catch (error) {
            setTerminal('Status 401 Unauthorized: Proactive Filter Blocked Payload.', 'blocked');
        } finally {
            setButtonLoading(verifyBtn, false, 'Verify & Route Token');
        }
    });

    // ================================================================
    //  EVENT: Token textarea input
    // ================================================================

    tokenInput.addEventListener('input', function () {
        updateLabControls(!!tokenInput.value.trim());
    });

    // ================================================================
    //  EVENT: Create Order
    // ================================================================

    orderForm.addEventListener('submit', async function (event) {
        event.preventDefault();
        var item = orderItem.value.trim();
        var quantity = parseInt(orderQuantity.value, 10);

        if (!item || !quantity || quantity < 1) {
            showStatus(orderStatus, 'Item name and valid quantity are required.');
            return;
        }
        if (!currentToken) {
            showStatus(orderStatus, 'No active session. Please sign in again.');
            return;
        }

        setButtonLoading(orderSubmitBtn, true, 'Creating...');

        try {
            var result = await apiRequest('/orders', {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + currentToken },
                body: JSON.stringify({ item: item, quantity: quantity })
            });

            if (result.response.ok) {
                orderForm.reset();
                orderQuantity.value = '1';
                hideStatus(orderStatus);
                setTerminal('Order created: ' + item + ' x' + quantity, 'ok');
                fetchOrders();
            } else {
                showStatus(orderStatus, extractErrorMessage(result.body, 'Failed to create order.'));
            }
        } catch (error) {
            showStatus(orderStatus, 'Network error: ' + error.message);
        } finally {
            setButtonLoading(orderSubmitBtn, false, 'Create Order');
        }
    });

    // ================================================================
    //  SESSION RESTORE (page load)
    // ================================================================

    async function tryRestoreSession() {
        // Cookie is sent automatically via credentials: 'include'
        try {
            var result = await apiRequest('/users/me', { method: 'GET' });
            if (result.response.ok && result.body) {
                var username = result.body.userId || 'User';

                // Fetch a fresh token for the lab via cookie-authenticated endpoint
                try {
                    var tokenResult = await apiRequest('/auth/token', { method: 'GET' });
                    if (tokenResult.response.ok && tokenResult.body && tokenResult.body.accessToken) {
                        enterDashboard(username, tokenResult.body.accessToken);
                        return true;
                    }
                } catch (e) { /* token fetch failed, continue without lab token */ }

                enterDashboard(username, null);
                return true;
            }
        } catch (e) { /* not authenticated */ }
        return false;
    }

    // ================================================================
    //  INIT
    // ================================================================

    tryRestoreSession().then(function (restored) {
        if (!restored) {
            showView('view-login');
        }
    });
})();

