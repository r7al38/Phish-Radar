// حالة التطبيق
let appState = {
    totalScans: 0,
    phishingCount: 0,
    safeCount: 0,
    todayScans: 0
};

// تهيئة التطبيق
document.addEventListener('DOMContentLoaded', function() {
    loadStatistics();
    setupEventListeners();
});

// إعداد مستمعي الأحداث
function setupEventListeners() {
    // Enter key في حقل URL
    document.getElementById('urlInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            scanUrl();
        }
    });
    
    // Enter key في الفحص المتعدد (Ctrl + Enter)
    document.getElementById('batchUrls').addEventListener('keydown', function(e) {
        if (e.ctrlKey && e.key === 'Enter') {
            batchScan();
        }
    });
}

// تحميل الإحصائيات
async function loadStatistics() {
    try {
        // في الواقع، ستأتي هذه البيانات من الخادم
        // هذه بيانات وهمية للعرض
        appState = {
            totalScans: 1247,
            phishingCount: 89,
            safeCount: 1158,
            todayScans: 23
        };
        
        updateStatisticsDisplay();
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

// تحديث عرض الإحصائيات
function updateStatisticsDisplay() {
    document.getElementById('totalScans').textContent = appState.totalScans.toLocaleString();
    document.getElementById('phishingCount').textContent = appState.phishingCount.toLocaleString();
    document.getElementById('safeCount').textContent = appState.safeCount.toLocaleString();
    document.getElementById('todayScans').textContent = appState.todayScans.toLocaleString();
}

// فحص رابط واحد
async function scanUrl() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    
    if (!url) {
        showNotification('يرجى إدخال رابط للفحص', 'warning');
        return;
    }
    
    if (!isValidUrl(url)) {
        showNotification('يرجى إدخال رابط صحيح', 'error');
        return;
    }
    
    // إظهار حالة التحميل
    showLoadingState();
    
    try {
        const response = await fetch('/advanced-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                url: url,
                deepScan: document.getElementById('deepScan').checked,
                apiCheck: document.getElementById('apiCheck').checked
            })
        });
        
        if (!response.ok) {
            throw new Error(`خطأ في الخادم: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (result.error) {
            throw new Error(result.error);
        }
        
        displayResult(result);
        updateAppStatistics(result);
        
    } catch (error) {
        showNotification(`خطأ في الفحص: ${error.message}`, 'error');
        hideLoadingState();
    }
}

// فحص متعدد
async function batchScan() {
    const urlsTextarea = document.getElementById('batchUrls');
    const urlsText = urlsTextarea.value.trim();
    
    if (!urlsText) {
        showNotification('يرجى إدخال روابط للفحص', 'warning');
        return;
    }
    
    const urls = urlsText.split('\n')
        .map(url => url.trim())
        .filter(url => url && isValidUrl(url));
    
    if (urls.length === 0) {
        showNotification('لم يتم العثور على روابط صالحة', 'error');
        return;
    }
    
    if (urls.length > 10) {
        showNotification('الحد الأقصى 10 روابط في المرة الواحدة', 'warning');
        return;
    }
    
    showBatchLoadingState(urls.length);
    
    try {
        const response = await fetch('/batch-advanced-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ urls: urls })
        });
        
        if (!response.ok) {
            throw new Error(`خطأ في الخادم: ${response.status}`);
        }
        
        const data = await response.json();
        displayBatchResults(data.results);
        
    } catch (error) {
        showNotification(`خطأ في الفحص المتعدد: ${error.message}`, 'error');
        hideLoadingState();
    }
}

// عرض نتيجة الفحص
function displayResult(result) {
    const resultSection = document.getElementById('resultSection');
    const resultContent = document.getElementById('resultContent');
    
    const verdict = result.final_verdict;
    const riskClass = `verdict-${verdict.risk_level}`;
    
    let html = `
        <div class="result-header ${riskClass}">
            <div class="verdict-main">
                <h3>
                    <i class="fas fa-${verdict.is_phishing ? 'exclamation-triangle' : 'check-circle'}"></i>
                    ${verdict.message}
                </h3>
                <div class="confidence-meter">
                    <div class="meter-fill" style="width: ${verdict.confidence * 100}%"></div>
                </div>
                <p class="confidence-text">ثقة النظام: ${(verdict.confidence * 100).toFixed(1)}%</p>
            </div>
        </div>
        
        <div class="result-details">
            <div class="detail-grid">
    `;
    
    // تحليل الذكاء الاصطناعي
    if (result.ai_analysis) {
        const ai = result.ai_analysis;
        html += `
            <div class="detail-item">
                <h4>
                    <i class="fas fa-robot"></i>
                    الذكاء الاصطناعي
                </h4>
                <p>الحكم: <strong>${ai.is_phishing ? 'تصيد' : 'آمن'}</strong></p>
                <p>الثقة: <strong>${(ai.confidence * 100).toFixed(1)}%</strong></p>
                <p>المستوى: <span class="risk-badge ${ai.risk_level}">${ai.risk_level}</span></p>
            </div>
        `;
    }
    
    // واجهات البرمجة
    if (result.api_results) {
        const apis = result.api_results;
        html += `
            <div class="detail-item">
                <h4>
                    <i class="fas fa-globe"></i>
                    الفحوصات الخارجية
                </h4>
                <p>VirusTotal: <strong>${apis.virustotal?.malicious || 0} / ${apis.virustotal?.total_engines || 0}</strong></p>
                <p>Google Safe: <strong>${apis.google_safebrowsing?.is_threat ? 'تهديد' : 'آمن'}</strong></p>
                <p>الخطورة: <strong>${(apis.overall_risk * 100).toFixed(1)}%</strong></p>
            </div>
        `;
    }
    
    // تحليل النص
    if (result.nlp_analysis) {
        const nlp = result.nlp_analysis;
        html += `
            <div class="detail-item">
                <h4>
                    <i class="fas fa-file-alt"></i>
                    تحليل النص
                </h4>
                <p>أنماط خطرة: <strong>${nlp.phishing_patterns?.urgency_indicators || 0}</strong></p>
                <p>خطورة النص: <strong>${(nlp.phishing_patterns?.phishing_risk_score * 100 || 0).toFixed(1)}%</strong></p>
                <p>المشاعر: <strong>${nlp.sentiment?.is_negative ? 'سلبية' : 'إيجابية'}</strong></p>
            </div>
        `;
    }
    
    // معلومات الموقع
    if (result.website_content) {
        const site = result.website_content;
        html += `
            <div class="detail-item">
                <h4>
                    <i class="fas fa-info-circle"></i>
                    معلومات الموقع
                </h4>
                <p>العنوان: <strong>${site.title || 'غير متوفر'}</strong></p>
                <p>النماذج: <strong>${site.has_forms ? 'موجودة' : 'غير موجودة'}</strong></p>
                <p>النص: <strong>${site.text_preview ? 'مستخرج' : 'غير متوفر'}</strong></p>
            </div>
        `;
    }
    
    html += `
            </div>
        </div>
        
        <div class="result-actions">
            <button class="btn-secondary" onclick="scanAgain()">
                <i class="fas fa-redo"></i>
                فحص رابط آخر
            </button>
            <button class="btn-primary" onclick="shareResult()">
                <i class="fas fa-share"></i>
                مشاركة النتيجة
            </button>
        </div>
    `;
    
    resultContent.innerHTML = html;
    resultSection.style.display = 'block';
    hideLoadingState();
    
    // Scroll to results
    resultSection.scrollIntoView({ behavior: 'smooth' });
}

// عرض نتائج الفحص المتعدد
function displayBatchResults(results) {
    const resultSection = document.getElementById('resultSection');
    const resultContent = document.getElementById('resultContent');
    
    let html = `
        <div class="result-header">
            <h3>
                <i class="fas fa-layer-group"></i>
                نتائج الفحص المتعدد
            </h3>
        </div>
        
        <div class="batch-results">
    `;
    
    results.forEach((result, index) => {
        const riskClass = result.error ? 'verdict-medium' : `verdict-${result.risk_level}`;
        
        html += `
            <div class="batch-result-item ${riskClass}">
                <div class="batch-result-header">
                    <span class="url-truncate">${result.url}</span>
                    <span class="verdict-badge ${result.risk_level}">
                        ${result.error ? 'خطأ' : result.verdict}
                    </span>
                </div>
                ${result.error ? `
                    <p class="error-message">${result.error}</p>
                ` : `
                    <div class="batch-result-details">
                        <span>الثقة: ${(result.confidence * 100).toFixed(1)}%</span>
                        <span>المستوى: ${result.risk_level}</span>
                    </div>
                `}
            </div>
        `;
    });
    
    html += `
        </div>
        
        <div class="result-actions">
            <button class="btn-secondary" onclick="scanAgain()">
                <i class="fas fa-redo"></i>
                فحص جديد
            </button>
        </div>
    `;
    
    resultContent.innerHTML = html;
    resultSection.style.display = 'block';
    hideLoadingState();
}

// تحديث إحصائيات التطبيق
function updateAppStatistics(result) {
    appState.totalScans++;
    appState.todayScans++;
    
    if (result.final_verdict.is_phishing) {
        appState.phishingCount++;
    } else {
        appState.safeCount++;
    }
    
    updateStatisticsDisplay();
}

// إظهار حالة التحميل
function showLoadingState() {
    const resultSection = document.getElementById('resultSection');
    const resultContent = document.getElementById('resultContent');
    
    resultContent.innerHTML = `
        <div class="loading-state">
            <div class="loading-spinner">
                <i class="fas fa-spinner fa-spin"></i>
            </div>
            <h3>جاري الفحص...</h3>
            <p>يتم الآن فحص الرابط باستخدام الذكاء الاصطناعي وقواعد البيانات العالمية</p>
            <div class="loading-steps">
                <div class="step active">
                    <i class="fas fa-check"></i>
                    التحقق من الرابط
                </div>
                <div class="step">
                    <i class="fas fa-robot"></i>
                    تحليل الذكاء الاصطناعي
                </div>
                <div class="step">
                    <i class="fas fa-globe"></i>
                    فحص قواعد البيانات
                </div>
                <div class="step">
                    <i class="fas fa-chart-bar"></i>
                    تحليل النتائج
                </div>
            </div>
        </div>
    `;
    
    resultSection.style.display = 'block';
    
    // محاكاة تقدم الخطوات
    const steps = document.querySelectorAll('.loading-steps .step');
    let currentStep = 0;
    
    const stepInterval = setInterval(() => {
        if (currentStep < steps.length) {
            steps[currentStep].classList.add('active');
            currentStep++;
        } else {
            clearInterval(stepInterval);
        }
    }, 800);
}

// إظهار حالة التحميل للفحص المتعدد
function showBatchLoadingState(count) {
    const resultSection = document.getElementById('resultSection');
    const resultContent = document.getElementById('resultContent');
    
    resultContent.innerHTML = `
        <div class="loading-state">
            <div class="loading-spinner">
                <i class="fas fa-spinner fa-spin"></i>
            </div>
            <h3>جاري فحص ${count} روابط...</h3>
            <p>يتم فحص الروابط بشكل تسلسلي للحصول على أفضل النتائج</p>
            <div class="progress-container">
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
                <span class="progress-text">0/${count}</span>
            </div>
        </div>
    `;
    
    resultSection.style.display = 'block';
}

// إخفاء حالة التحميل
function hideLoadingState() {
    // يتم استبدال المحتوى تلقائياً بالنتائج
}

// فحص رابط آخر
function scanAgain() {
    document.getElementById('urlInput').value = '';
    document.getElementById('batchUrls').value = '';
    document.getElementById('resultSection').style.display = 'none';
    document.getElementById('urlInput').focus();
}

// مشاركة النتيجة
function shareResult() {
    // في الواقع، قد تشارك عبر APIs مختلفة
    showNotification('سيتم إضافة ميزة المشاركة قريباً', 'info');
}

// إظهار الإشعارات
function showNotification(message, type = 'info') {
    // إنشاء عنصر الإشعار
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${getNotificationIcon(type)}"></i>
            <span>${message}</span>
        </div>
        <button class="notification-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // إضافة الأنماط
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${getNotificationColor(type)};
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 1000;
        display: flex;
        align-items: center;
        gap: 10px;
        max-width: 400px;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    // إزالة تلقائية بعد 5 ثواني
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

function getNotificationIcon(type) {
    const icons = {
        'success': 'check-circle',
        'error': 'exclamation-circle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

function getNotificationColor(type) {
    const colors = {
        'success': '#28a745',
        'error': '#dc3545',
        'warning': '#ffc107',
        'info': '#17a2b8'
    };
    return colors[type] || '#17a2b8';
}

// التحقق من صحة URL
function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

// إظهار/إخفاء النماذج
function showAbout() {
    document.getElementById('aboutModal').style.display = 'flex';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

// إغلاق النماذج بالنقر خارجها
window.onclick = function(event) {
    const modals = document.getElementsByClassName('modal');
    for (let modal of modals) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    }
};

// إضافة أنيميشن للإشعارات
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    .notification-close {
        background: none;
        border: none;
        color: white;
        cursor: pointer;
        padding: 0;
        margin-right: 0;
    }
    
    .risk-badge {
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 0.8em;
        font-weight: bold;
    }
    
    .risk-badge.high {
        background: var(--danger-color);
        color: white;
    }
    
    .risk-badge.medium {
        background: var(--warning-color);
        color: black;
    }
    
    .risk-badge.low {
        background: var(--success-color);
        color: white;
    }
    
    .loading-steps .step {
        opacity: 0.5;
        transition: opacity 0.3s ease;
    }
    
    .loading-steps .step.active {
        opacity: 1;
    }
    
    .progress-container {
        margin-top: 15px;
    }
    
    .progress-bar {
        width: 100%;
        height: 8px;
        background: var(--border-color);
        border-radius: 4px;
        overflow: hidden;
    }
    
    .progress-fill {
        height: 100%;
        background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
        transition: width 0.3s ease;
    }
    
    .progress-text {
        display: block;
        text-align: center;
        margin-top: 5px;
        font-size: 0.9em;
        color: var(--text-muted);
    }
`;
document.head.appendChild(style);