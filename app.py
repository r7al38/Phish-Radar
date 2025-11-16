from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json
from datetime import datetime
import os
from ai_engine import AdvancedAIEngine
from api_integration import APIIntegration
from nlp_analyzer import AdvancedNLPAnalyzer
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)
CORS(app)

# تهيئة المحركات
ai_engine = AdvancedAIEngine()
api_integration = APIIntegration()
nlp_analyzer = AdvancedNLPAnalyzer()

def extract_website_content(url):
    """استخراج محتوى الموقع"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # استخراج النص
        text_content = soup.get_text(separator=' ', strip=True)
        
        # تنظيف النص
        lines = (line.strip() for line in text_content.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        clean_text = ' '.join(chunk for chunk in chunks if chunk)
        
        return {
            'html': str(soup),
            'text': clean_text[:5000],  # الحد الأقصى 5000 حرف
            'title': soup.title.string if soup.title else '',
            'meta_description': soup.find('meta', attrs={'name': 'description'})
        }
        
    except Exception as e:
        return {'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/advanced-scan', methods=['POST'])
def advanced_scan():
    """فحص متقدم باستخدام الذكاء الاصطناعي"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'يرجى إدخال رابط'})
    
    print(f"🔍 بدء الفحص المتقدم: {url}")
    
    try:
        # 1. استخراج محتوى الموقع
        print("📄 جاري استخراج محتوى الموقع...")
        website_content = extract_website_content(url)
        
        # 2. تحليل باستخدام الذكاء الاصطناعي
        print("🤖 جاري التحليل بالذكاء الاصطناعي...")
        features = ai_engine.extract_advanced_features(
            url, 
            html_content=website_content.get('html'),
            text_content=website_content.get('text')
        )
        
        ai_prediction = ai_engine.predict_phishing(features)
        
        # 3. تحليل النص باستخدام NLP
        print("📊 جاري تحليل النص...")
        nlp_analysis = {}
        if website_content.get('text'):
            nlp_analysis = nlp_analyzer.analyze_text_content(website_content.get('text'))
        
        # 4. فحص باستخدام واجهات البرمجة
        print("🌐 جاري الفحص عبر واجهات البرمجة...")
        api_results = api_integration.comprehensive_api_check(url)
        
        # 5. تجميع النتائج
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'ai_analysis': ai_prediction,
            'nlp_analysis': nlp_analysis,
            'api_results': api_results,
            'website_content': {
                'title': website_content.get('title'),
                'text_preview': website_content.get('text', '')[:500] + '...' if website_content.get('text') else '',
                'has_forms': 'form' in website_content.get('html', '').lower()
            },
            'features': features
        }
        
        # 6. تحديد النتيجة النهائية
        result['final_verdict'] = calculate_final_verdict(result)
        
        print(f"✅ اكتمل الفحص: {result['final_verdict']}")
        
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ خطأ في الفحص: {e}")
        return jsonify({'error': f'خطأ في الفحص: {str(e)}'})

def calculate_final_verdict(result):
    """حساب الحكم النهائي بناءً على جميع العوامل"""
    scores = []
    
    # نتيجة الذكاء الاصطناعي
    ai_score = result['ai_analysis']['confidence']
    if result['ai_analysis']['is_phishing']:
        scores.append(ai_score)
    
    # نتيجة واجهات البرمجة
    api_score = result['api_results'].get('overall_risk', 0)
    if api_score > 0.3:
        scores.append(api_score)
    
    # نتيجة تحليل النص
    nlp_score = result.get('nlp_analysis', {}).get('phishing_patterns', {}).get('phishing_risk_score', 0)
    if nlp_score > 0.4:
        scores.append(nlp_score)
    
    if not scores:
        return {
            'is_phishing': False,
            'confidence': max(1 - ai_score, 0.1),
            'risk_level': 'low',
            'message': '✅ الرابط يبدو آمناً'
        }
    
    # المتوسط المرجح
    final_score = sum(scores) / len(scores)
    
    if final_score > 0.7:
        return {
            'is_phishing': True,
            'confidence': final_score,
            'risk_level': 'high',
            'message': '🛑 تصيد عالي الخطورة!'
        }
    elif final_score > 0.4:
        return {
            'is_phishing': True,
            'confidence': final_score,
            'risk_level': 'medium',
            'message': '⚠️ مشبوه - تجنب استخدامه'
        }
    else:
        return {
            'is_phishing': False,
            'confidence': 1 - final_score,
            'risk_level': 'low',
            'message': '✅ آمن - خطورة منخفضة'
        }

@app.route('/batch-advanced-scan', methods=['POST'])
def batch_advanced_scan():
    """فحص متعدد متقدم"""
    data = request.get_json()
    urls = [url.strip() for url in data.get('urls', '').split('\n') if url.strip()]
    
    results = []
    for url in urls[:5]:  # حد أقصى 5 روابط
        try:
            result = advanced_scan_single(url)
            results.append(result)
        except Exception as e:
            results.append({
                'url': url,
                'error': str(e)
            })
    
    return jsonify({'results': results})

def advanced_scan_single(url):
    """نسخة مبسطة للفحص الفردي"""
    website_content = extract_website_content(url)
    features = ai_engine.extract_advanced_features(
        url,
        html_content=website_content.get('html'),
        text_content=website_content.get('text')
    )
    prediction = ai_engine.predict_phishing(features)
    
    return {
        'url': url,
        'verdict': '🛑 تصيد' if prediction['is_phishing'] else '✅ آمن',
        'confidence': prediction['confidence'],
        'risk_level': prediction['risk_level']
    }

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)