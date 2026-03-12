document.addEventListener('DOMContentLoaded', function () {
    initFileUpload();
    initAnimatedCounters();
    initNavbarScroll();
});

function initFileUpload() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileName = document.getElementById('fileName');

    if (!dropZone || !fileInput) return;

    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            showFileName(files[0].name);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            showFileName(fileInput.files[0].name);
        }
    });

    function showFileName(name) {
        if (fileName) {
            fileName.innerHTML = '<i class="fas fa-file-csv me-1"></i> ' + name;
        }
    }
}

function initAnimatedCounters() {
    const counters = document.querySelectorAll('[data-count]');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const el = entry.target;
                const target = parseFloat(el.getAttribute('data-count'));
                animateCount(el, 0, target, 1500);
                observer.unobserve(el);
            }
        });
    }, { threshold: 0.5 });

    counters.forEach(counter => observer.observe(counter));
}

function animateCount(el, start, end, duration) {
    const startTime = performance.now();
    const isFloat = end % 1 !== 0;

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = start + (end - start) * eased;

        el.textContent = isFloat ? current.toFixed(1) : Math.round(current);

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

function initNavbarScroll() {
    const navbar = document.querySelector('.navbar');
    if (!navbar) return;

    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.style.background = 'rgba(10, 10, 26, 0.98)';
            navbar.style.boxShadow = '0 2px 20px rgba(0, 0, 0, 0.5)';
        } else {
            navbar.style.background = 'rgba(10, 10, 26, 0.95)';
            navbar.style.boxShadow = 'none';
        }
    });
}

function initDashboardCharts(attackTypes) {
    if (!attackTypes || Object.keys(attackTypes).length === 0) return;

    const labels = Object.keys(attackTypes);
    const data = Object.values(attackTypes);
    const colors = generateColors(labels);

    const pieCtx = document.getElementById('attackPieChart');
    if (pieCtx) {
        new Chart(pieCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors.bg,
                    borderColor: colors.border,
                    borderWidth: 2,
                    hoverOffset: 10,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#e0e0e0', padding: 15, font: { family: "'Roboto', sans-serif", size: 12 } }
                    }
                },
                cutout: '55%',
            }
        });
    }

    const barCtx = document.getElementById('attackBarChart');
    if (barCtx) {
        new Chart(barCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Detections',
                    data: data,
                    backgroundColor: colors.bg,
                    borderColor: colors.border,
                    borderWidth: 1,
                    borderRadius: 6,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, ticks: { color: '#888' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    x: { ticks: { color: '#888' }, grid: { display: false } }
                }
            }
        });
    }
}

function initFeatureImportanceChart(featureImportances) {
    const ctx = document.getElementById('featureImportanceChart');
    if (!ctx || !featureImportances) return;

    const sorted = Object.entries(featureImportances)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15);

    const labels = sorted.map(item => item[0]);
    const data = sorted.map(item => (item[1] * 100).toFixed(2));

    new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Importance (%)',
                data: data,
                backgroundColor: 'rgba(0, 255, 136, 0.3)',
                borderColor: 'rgba(0, 255, 136, 0.8)',
                borderWidth: 1,
                borderRadius: 4,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { beginAtZero: true, ticks: { color: '#888' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: '#00ff88', font: { family: "'Fira Code', monospace", size: 11 } }, grid: { display: false } }
            }
        }
    });
}

function generateColors(labels) {
    const colorMap = {
        'Normal': { bg: 'rgba(0, 255, 136, 0.6)', border: '#00ff88' },
        'DoS': { bg: 'rgba(233, 69, 96, 0.6)', border: '#e94560' },
        'Probe': { bg: 'rgba(249, 202, 36, 0.6)', border: '#f9ca24' },
        'R2L': { bg: 'rgba(0, 212, 255, 0.6)', border: '#00d4ff' },
        'U2R': { bg: 'rgba(155, 89, 182, 0.6)', border: '#9b59b6' },
    };

    const fallback = [
        { bg: 'rgba(52, 152, 219, 0.6)', border: '#3498db' },
        { bg: 'rgba(46, 204, 113, 0.6)', border: '#2ecc71' },
        { bg: 'rgba(231, 76, 60, 0.6)', border: '#e74c3c' },
        { bg: 'rgba(241, 196, 15, 0.6)', border: '#f1c40f' },
        { bg: 'rgba(155, 89, 182, 0.6)', border: '#9b59b6' },
    ];

    const bgColors = [];
    const borderColors = [];

    labels.forEach((label, i) => {
        if (colorMap[label]) {
            bgColors.push(colorMap[label].bg);
            borderColors.push(colorMap[label].border);
        } else {
            const fb = fallback[i % fallback.length];
            bgColors.push(fb.bg);
            borderColors.push(fb.border);
        }
    });

    return { bg: bgColors, border: borderColors };
}