import requests
import json
import time
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

class APIIntegration:
    def __init__(self):
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.google_safebrowsing_key = os.getenv('GOOGLE_SAFEBROWSING_API_KEY')
        self.urlscan_api_key = os.getenv('URLSCAN_API_KEY')
    
    def check_virustotal(self, url):
        """التحقق من سمعة الرابط على VirusTotal"""
        if not self.virustotal_api_key:
            return {'error': 'مفتاح VirusTotal غير متوفر'}
        
        try:
            # تحويل URL إلى SHA256 (للبحث)
            import hashlib
            url_id = hashlib.sha256(url.encode()).hexdigest()
            
            headers = {
                'x-apikey': self.virustotal_api_key
            }
            
            # البحث في قاعدة البيانات
            response = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                result = {
                    'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                    'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                    'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                    'harmless': attributes.get('last_analysis_stats', {}).get('harmless', 0),
                    'reputation': attributes.get('reputation', 0),
                    'total_engines': sum(attributes.get('last_analysis_stats', {}).values())
                }
                
                result['risk_score'] = (result['malicious'] + result['suspicious'] * 0.5) / max(result['total_engines'], 1)
                return result
                
            else:
                return {'error': f'خطأ في API: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'خطأ في الاتصال: {str(e)}'}
    
    def check_google_safebrowsing(self, url):
        """التحقق من الرابط باستخدام Google Safe Browsing"""
        if not self.google_safebrowsing_key:
            return {'error': 'مفتاح Google Safe Browsing غير متوفر'}
        
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_safebrowsing_key}"
            
            payload = {
                "client": {
                    "clientId": "phishing-detector",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'matches' in data:
                    threats = [match['threatType'] for match in data['matches']]
                    return {
                        'is_threat': True,
                        'threat_types': threats,
                        'risk_level': 'high'
                    }
                else:
                    return {
                        'is_threat': False,
                        'threat_types': [],
                        'risk_level': 'low'
                    }
            else:
                return {'error': f'خطأ في API: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'خطأ في الاتصال: {str(e)}'}
    
    def scan_with_urlscan(self, url):
        """فحص الرابط باستخدام urlscan.io"""
        if not self.urlscan_api_key:
            return {'error': 'مفتاح urlscan.io غير متوفر'}
        
        try:
            headers = {
                'API-Key': self.urlscan_api_key,
                'Content-Type': 'application/json'
            }
            
            # إرسال طلب الفحص
            scan_data = {
                "url": url,
                "visibility": "public"
            }
            
            response = requests.post(
                'https://urlscan.io/api/v1/scan/',
                headers=headers,
                json=scan_data,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                scan_id = data.get('uuid')
                
                # الانتظار لنتيجة الفحص
                time.sleep(5)
                
                # جلب النتائج
                result_response = requests.get(
                    f'https://urlscan.io/api/v1/result/{scan_id}/',
                    timeout=10
                )
                
                if result_response.status_code == 200:
                    result_data = result_response.json()
                    
                    # تحليل النتائج
                    verdict = result_data.get('verdicts', {})
                    return {
                        'malicious': verdict.get('overall', {}).get('malicious', False),
                        'score': verdict.get('overall', {}).get('score', 0),
                        'categories': verdict.get('overall', {}).get('categories', []),
                        'page_url': result_data.get('page', {}).get('url', '')
                    }
                else:
                    return {'error': 'تعذر جلب نتائج الفحص'}
            else:
                return {'error': f'خطأ في بدء الفحص: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'خطأ في الاتصال: {str(e)}'}
    
    def check_phishing_database(self, url):
        """التحقق من قواعد البيانات المفتوحة"""
        try:
            # التحقق من PhishTank
            phishtank_response = requests.get(
                f'http://checkurl.phishtank.com/checkurl/',
                params={
                    'url': url,
                    'format': 'json',
                    'app_key': 'YOUR_PHISHTANK_API_KEY'  # احصل على مفتاح من phishtank.org
                },
                timeout=10
            )
            
            results = {}
            
            if phishtank_response.status_code == 200:
                phishtank_data = phishtank_response.json()
                results['phishtank'] = {
                    'in_database': phishtank_data.get('results', {}).get('in_database', False),
                    'valid': phishtank_data.get('results', {}).get('valid', False)
                }
            
            # يمكن إضافة المزيد من APIs هنا
            
            return results
            
        except Exception as e:
            return {'error': f'خطأ في فحص قواعد البيانات: {str(e)}'}
    
    def comprehensive_api_check(self, url):
        """فحص شامل باستخدام جميع واجهات البرمجة"""
        print(f"🔍 بدء الفحص الشامل للرابط: {url}")
        
        results = {
            'virustotal': {},
            'google_safebrowsing': {},
            'urlscan': {},
            'phishing_databases': {}
        }
        
        # فحص VirusTotal
        print("🔄 جاري فحص VirusTotal...")
        results['virustotal'] = self.check_virustotal(url)
        time.sleep(1)  # تجنب rate limiting
        
        # فحص Google Safe Browsing
        print("🔄 جاري فحص Google Safe Browsing...")
        results['google_safebrowsing'] = self.check_google_safebrowsing(url)
        time.sleep(1)
        
        # فحص urlscan.io
        print("🔄 جاري فحص urlscan.io...")
        results['urlscan'] = self.scan_with_urlscan(url)
        time.sleep(1)
        
        # فحص قواعد البيانات
        print("🔄 جاري فحص قواعد البيانات...")
        results['phishing_databases'] = self.check_phishing_database(url)
        
        # حساب نتيجة عامة
        results['overall_risk'] = self._calculate_overall_risk(results)
        
        return results
    
    def _calculate_overall_risk(self, api_results):
        """حساب درجة الخطورة الإجمالية"""
        risk_score = 0
        factors = 0
        
        # VirusTotal
        vt = api_results.get('virustotal', {})
        if 'risk_score' in vt:
            risk_score += vt['risk_score']
            factors += 1
        
        # Google Safe Browsing
        gsb = api_results.get('google_safebrowsing', {})
        if gsb.get('is_threat'):
            risk_score += 1.0
            factors += 1
        
        # urlscan.io
        us = api_results.get('urlscan', {})
        if us.get('malicious'):
            risk_score += 1.0
            factors += 1
        
        # متوسط الخطورة
        if factors > 0:
            return risk_score / factors
        return 0.0

# اختبار التكامل
if __name__ == "__main__":
    api = APIIntegration()
    
    test_url = "http://example.com"
    results = api.comprehensive_api_check(test_url)
    
    print("📊 نتائج فحص APIs:")
    for service, result in results.items():
        print(f"{service.upper()}: {result}")