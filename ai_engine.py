import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel, pipeline
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import requests
import re
from textblob import TextBlob
from langdetect import detect, LangDetectException
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer

# تحميل نماذج NLTK (لأول مرة فقط)
try:
    nltk.data.find('sentiment/vader_lexicon')
except:
    nltk.download('vader_lexicon')

class AdvancedAIEngine:
    def __init__(self):
        self.tokenizer = None
        self.model = None
        self.vectorizer = None
        self.classifier = None
        self.sentiment_analyzer = SentimentIntensityAnalyzer()
        self.load_models()
    
    def load_models(self):
        """تحميل النماذج المدربة"""
        try:
            # تحميل نموذج BERT للغة العربية/الإنجليزية
            self.tokenizer = AutoTokenizer.from_pretrained("bert-base-multilingual-uncased")
            self.model = AutoModel.from_pretrained("bert-base-multilingual-uncased")
            
            # تحميل مصنف محلي (إذا موجود)
            try:
                self.vectorizer = joblib.load('models/tfidf_vectorizer.pkl')
                self.classifier = joblib.load('models/phishing_classifier.pkl')
            except:
                print("النماذج المحلية غير موجودة، سيتم استخدام النماذج الأساسية")
                
        except Exception as e:
            print(f"خطأ في تحميل النماذج: {e}")
    
    def extract_advanced_features(self, url, html_content=None, text_content=None):
        """استخراج خصائص متقدمة"""
        features = {}
        
        # 1. خصائص URL الأساسية
        features.update(self._extract_url_features(url))
        
        # 2. خصائص النص (إذا وجد)
        if text_content:
            features.update(self._extract_text_features(text_content))
        
        # 3. خصائص HTML (إذا وجد)
        if html_content:
            features.update(self._extract_html_features(html_content))
        
        # 4. خصائص الذكاء الاصطناعي
        features.update(self._extract_ai_features(url, text_content))
        
        return features
    
    def _extract_url_features(self, url):
        """استخراج خصائص URL"""
        features = {}
        
        # تحليل URL
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscore'] = url.count('_')
        features['num_slash'] = url.count('/')
        features['has_https'] = 1 if url.startswith('https') else 0
        features['has_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', url) else 0
        
        # كلمات مشبوهة
        suspicious_words = ['login', 'verify', 'account', 'bank', 'secure', 'update',
                           'confirm', 'password', 'credential', 'urgent', 'immediately']
        features['suspicious_words_count'] = sum(1 for word in suspicious_words if word in url.lower())
        
        # إحصائيات الأحرف
        features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url) if url else 0
        features['letter_ratio'] = sum(c.isalpha() for c in url) / len(url) if url else 0
        
        return features
    
    def _extract_text_features(self, text):
        """استخراج خصائص النص"""
        features = {}
        
        if not text:
            return features
        
        # تحليل المشاعر
        sentiment_scores = self.sentiment_analyzer.polarity_scores(text)
        features['sentiment_compound'] = sentiment_scores['compound']
        features['sentiment_positive'] = sentiment_scores['pos']
        features['sentiment_negative'] = sentiment_scores['neg']
        features['sentiment_neutral'] = sentiment_scores['neu']
        
        # تحليل TextBlob
        try:
            blob = TextBlob(text)
            features['textblob_polarity'] = blob.sentiment.polarity
            features['textblob_subjectivity'] = blob.sentiment.subjectivity
        except:
            features['textblob_polarity'] = 0
            features['textblob_subjectivity'] = 0
        
        # إحصائيات النص
        features['text_length'] = len(text)
        features['word_count'] = len(text.split())
        features['avg_word_length'] = np.mean([len(word) for word in text.split()]) if text.split() else 0
        
        # كلمات الطوارئ
        urgency_words = ['urgent', 'immediately', 'now', 'quick', 'alert', 'warning',
                        'important', 'action required', 'verify now']
        features['urgency_words_count'] = sum(1 for word in urgency_words if word in text.lower())
        
        return features
    
    def _extract_html_features(self, html):
        """استخراج خصائص HTML"""
        features = {}
        
        # عد العناصر
        features['form_count'] = html.count('<form')
        features['input_count'] = html.count('<input')
        features['password_count'] = html.count('type="password"')
        features['script_count'] = html.count('<script')
        features['link_count'] = html.count('<a href')
        
        # نسبة النص إلى HTML
        text_length = len(re.sub('<[^<]+?>', '', html))
        features['text_html_ratio'] = text_length / len(html) if html else 0
        
        return features
    
    def _extract_ai_features(self, url, text):
        """استخراج خصائص باستخدام الذكاء الاصطناعي"""
        features = {}
        
        # تحليل BERT للنص (إذا وجد)
        if text and self.tokenizer and self.model:
            try:
                inputs = self.tokenizer(text[:512], return_tensors="pt", truncation=True, max_length=512)
                with torch.no_grad():
                    outputs = self.model(**inputs)
                embeddings = outputs.last_hidden_state.mean(dim=1).numpy()[0]
                
                # أخذ أول 10 قيم من الـ embeddings كميزات
                for i in range(min(10, len(embeddings))):
                    features[f'bert_embedding_{i}'] = embeddings[i]
                    
            except Exception as e:
                print(f"خطأ في تحليل BERT: {e}")
        
        # كشف اللغة
        try:
            if text:
                lang = detect(text)
                features['is_english'] = 1 if lang == 'en' else 0
                features['is_arabic'] = 1 if lang == 'ar' else 0
        except LangDetectException:
            features['is_english'] = 0
            features['is_arabic'] = 0
        
        return features
    
    def predict_phishing(self, features):
        """التنبؤ باستخدام الذكاء الاصطناعي"""
        if not self.classifier:
            # استخدام قاعدة بسيطة إذا لم يكن المصنف متاحاً
            risk_score = self._calculate_risk_score(features)
            return {
                'is_phishing': risk_score > 0.6,
                'confidence': risk_score,
                'risk_level': 'high' if risk_score > 0.7 else 'medium' if risk_score > 0.4 else 'low'
            }
        
        try:
            # تحويل الميزات لمصفوفة
            feature_array = np.array([list(features.values())]).reshape(1, -1)
            
            # التنبؤ
            prediction = self.classifier.predict(feature_array)[0]
            probability = self.classifier.predict_proba(feature_array)[0]
            
            confidence = probability[1] if prediction else probability[0]
            
            return {
                'is_phishing': bool(prediction),
                'confidence': float(confidence),
                'risk_level': 'high' if confidence > 0.8 else 'medium' if confidence > 0.5 else 'low'
            }
            
        except Exception as e:
            print(f"خطأ في التنبؤ: {e}")
            risk_score = self._calculate_risk_score(features)
            return {
                'is_phishing': risk_score > 0.6,
                'confidence': risk_score,
                'risk_level': 'high' if risk_score > 0.7 else 'medium' if risk_score > 0.4 else 'low'
            }
    
    def _calculate_risk_score(self, features):
        """حساب درجة الخطورة يدوياً"""
        risk_score = 0
        
        # عوامل الخطورة
        if features.get('suspicious_words_count', 0) > 3:
            risk_score += 0.3
        
        if features.get('url_length', 0) > 75:
            risk_score += 0.2
        
        if features.get('has_ip', 0) == 1:
            risk_score += 0.3
        
        if features.get('urgency_words_count', 0) > 2:
            risk_score += 0.2
        
        if features.get('sentiment_negative', 0) > 0.5:
            risk_score += 0.1
        
        if features.get('password_count', 0) > 0:
            risk_score += 0.2
        
        return min(risk_score, 1.0)

# اختبار المحرك
if __name__ == "__main__":
    ai_engine = AdvancedAIEngine()
    
    # اختبار نموذجي
    test_url = "http://paypal-security-verify.com/login"
    test_text = "Urgent: Your account has been suspended. Verify your credentials immediately."
    
    features = ai_engine.extract_advanced_features(test_url, text_content=test_text)
    prediction = ai_engine.predict_phishing(features)
    
    print("🔍 نتائج الاختبار:")
    print(f"الرابط: {test_url}")
    print(f"التنبؤ: {'تصيد' if prediction['is_phishing'] else 'آمن'}")
    print(f"الثقة: {prediction['confidence']:.2%}")
    print(f"مستوى الخطورة: {prediction['risk_level']}")