import re
import numpy as np
from transformers import pipeline
import torch
from langdetect import detect
from textblob import TextBlob
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords

class AdvancedNLPAnalyzer:
    def __init__(self):
        self.sentiment_analyzer = pipeline("sentiment-analysis")
        self.toxicity_analyzer = pipeline("text-classification", 
                                         model="unitary/toxic-bert")
        
        # تحميل stopwords
        try:
            nltk.data.find('tokenizers/punkt')
        except:
            nltk.download('punkt')
        
        try:
            nltk.data.find('corpora/stopwords')
        except:
            nltk.download('stopwords')
    
    def analyze_text_content(self, text):
        """تحليل متقدم للنص"""
        if not text or len(text.strip()) < 10:
            return {'error': 'نص قصير جداً للتحليل'}
        
        analysis = {}
        
        # 1. تحليل المشاعر
        analysis['sentiment'] = self._analyze_sentiment(text)
        
        # 2. تحليل السمية
        analysis['toxicity'] = self._analyze_toxicity(text)
        
        # 3. خصائص النص
        analysis['text_features'] = self._extract_text_features(text)
        
        # 4. كشف أنماط التصيد
        analysis['phishing_patterns'] = self._detect_phishing_patterns(text)
        
        # 5. تحليل اللغة
        analysis['language'] = self._analyze_language(text)
        
        return analysis
    
    def _analyze_sentiment(self, text):
        """تحليل المشاعر"""
        try:
            # استخدام transformers
            result = self.sentiment_analyzer(text[:512])[0]
            
            # استخدام TextBlob للتحقق
            blob = TextBlob(text)
            polarity = blob.sentiment.polarity
            
            return {
                'label': result['label'],
                'confidence': result['score'],
                'polarity': polarity,
                'is_negative': polarity < -0.3 or result['label'] == 'NEGATIVE'
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_toxicity(self, text):
        """تحليل السمية والمحتوى الضار"""
        try:
            result = self.toxicity_analyzer(text[:512])[0]
            return {
                'label': result['label'],
                'score': result['score'],
                'is_toxic': result['score'] > 0.7
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_text_features(self, text):
        """استخراج خصائص النص"""
        features = {}
        
        # إحصائيات أساسية
        features['char_count'] = len(text)
        features['word_count'] = len(text.split())
        features['sentence_count'] = len(re.split(r'[.!?]+', text))
        
        # تعقيد النص
        features['avg_word_length'] = np.mean([len(word) for word in text.split()])
        features['avg_sentence_length'] = features['word_count'] / max(features['sentence_count'], 1)
        
        # تنوع المفردات
        words = text.lower().split()
        unique_words = set(words)
        features['vocab_richness'] = len(unique_words) / len(words) if words else 0
        
        # علامات الترقيم
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['uppercase_ratio'] = sum(1 for c in text if c.isupper()) / len(text)
        
        return features
    
    def _detect_phishing_patterns(self, text):
        """كشف أنماط التصيد في النص"""
        patterns = {
            'urgency_indicators': 0,
            'authority_claims': 0,
            'reward_promises': 0,
            'threats': 0,
            'personal_requests': 0
        }
        
        text_lower = text.lower()
        
        # كلمات الطوارئ
        urgency_words = ['urgent', 'immediately', 'now', 'quick', 'asap', 'right away',
                        'instant', 'emergency', 'important', 'action required']
        patterns['urgency_indicators'] = sum(1 for word in urgency_words if word in text_lower)
        
        # ادعاءات سلطة
        authority_words = ['security', 'verify', 'confirm', 'validate', 'official',
                          'government', 'bank', 'administration', 'support']
        patterns['authority_claims'] = sum(1 for word in authority_words if word in text_lower)
        
        # وعود مكافآت
        reward_words = ['free', 'winner', 'congratulations', 'prize', 'reward',
                       'bonus', 'gift', 'selected', 'exclusive']
        patterns['reward_promises'] = sum(1 for word in reward_words if word in text_lower)
        
        # تهديدات
        threat_words = ['suspend', 'close', 'terminate', 'block', 'limit',
                       'restrict', 'penalty', 'fine', 'legal']
        patterns['threats'] = sum(1 for word in threat_words if word in text_lower)
        
        # طلبات شخصية
        personal_words = ['your account', 'your password', 'your credentials',
                         'your information', 'your data', 'click here', 'login now']
        patterns['personal_requests'] = sum(1 for word in personal_words if word in text_lower)
        
        # حساب درجة الخطورة
        total_indicators = sum(patterns.values())
        patterns['phishing_risk_score'] = min(total_indicators / 10, 1.0)
        patterns['is_high_risk'] = patterns['phishing_risk_score'] > 0.6
        
        return patterns
    
    def _analyze_language(self, text):
        """تحليل اللغة والتركيب"""
        try:
            # كشف اللغة
            lang = detect(text)
            
            # تحليل النحو (بسيط)
            sentences = re.split(r'[.!?]+', text)
            avg_sentence_complexity = np.mean([len(word_tokenize(sent)) for sent in sentences if sent.strip()])
            
            return {
                'detected_language': lang,
                'avg_sentence_length': avg_sentence_complexity,
                'is_english': lang == 'en',
                'is_arabic': lang == 'ar'
            }
        except Exception as e:
            return {'error': str(e)}