/**
 * SecureShop — Commercial E-Commerce Frontend Interactions
 */

document.addEventListener('DOMContentLoaded', function () {

    // 1. Auto-dismiss flash alerts after 5.5 seconds
    const alerts = document.querySelectorAll('.alert.alert-dismissible');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            try {
                const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
                bsAlert.close();
            } catch (e) {
                // Ignore if already closed
            }
        }, 5500);
    });

    // 2. Confirm dangerous actions
    const dangerForms = document.querySelectorAll('form[data-confirm]');
    dangerForms.forEach(function (form) {
        form.addEventListener('submit', function (e) {
            if (!confirm(form.dataset.confirm)) {
                e.preventDefault();
            }
        });
    });

    // 3. Password visibility toggle buttons
    document.querySelectorAll('[data-toggle-password]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const targetId = btn.getAttribute('data-toggle-password');
            const input = document.getElementById(targetId);
            if (!input) return;

            const icon = btn.querySelector('i');
            if (input.type === 'password') {
                input.type = 'text';
                if (icon) {
                    icon.classList.remove('bi-eye');
                    icon.classList.add('bi-eye-slash');
                }
                btn.setAttribute('aria-label', 'Hide password');
            } else {
                input.type = 'password';
                if (icon) {
                    icon.classList.remove('bi-eye-slash');
                    icon.classList.add('bi-eye');
                }
                btn.setAttribute('aria-label', 'Show password');
            }
        });
    });

    // 4. Quantity +/- stepper controls
    document.querySelectorAll('[data-qty-step]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const step = parseInt(btn.getAttribute('data-qty-step'), 10) || 0;
            const wrapper = btn.closest('.qty-stepper-group');
            const input = wrapper ? wrapper.querySelector('input[name="quantity"]') : null;
            if (!input) return;

            const min = parseInt(input.min, 10) || 1;
            const max = parseInt(input.max, 10) || 999;
            let current = parseInt(input.value, 10) || min;
            let next = current + step;
            if (next < min) next = min;
            if (next > max) next = max;
            input.value = next;
        });
    });

    // 5. Quantity input bounds check
    const qtyInputs = document.querySelectorAll('input[type="number"][name="quantity"]');
    qtyInputs.forEach(function (input) {
        input.addEventListener('change', function () {
            const min = parseInt(input.min, 10) || 0;
            const max = parseInt(input.max, 10) || 999;
            let val = parseInt(input.value, 10);
            if (isNaN(val) || val < min) val = min;
            if (val > max) val = max;
            input.value = val;
        });
    });

    // 6. Active nav link highlighting
    const currentPath = window.location.pathname;
    document.querySelectorAll('.secureshop-navbar .navbar-nav .nav-link').forEach(function (link) {
        const href = link.getAttribute('href');
        if (
            href === currentPath
            || (href === '/products' && currentPath.startsWith('/product/'))
            || (href && href.startsWith('/admin/security-lab') && currentPath.startsWith('/admin/security-lab'))
        ) {
            link.classList.add('active');
        }
    });

    // 7. Graceful fallback for product images
    document.querySelectorAll('img.product-image, img.order-mini-thumb, img.product-detail-img').forEach(function (img) {
        img.addEventListener('error', function () {
            if (!img.dataset.fallbackApplied) {
                img.dataset.fallbackApplied = 'true';
                img.src = '/static/images/product-placeholder.svg';
            }
        });
    });

});
