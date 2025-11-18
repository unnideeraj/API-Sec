<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

## Beginner-Friendly Roadmap: Building an AI/ML-Powered API Security Module

Building an AI/ML-powered Web Application and API Protection (WAAP) system as a reverse proxy requires structured learning and implementation. Here's your comprehensive step-by-step roadmap based on your Python API security module foundation.[^1_1][^1_2][^1_3]

### Phase 1: Foundation \& Environment Setup (Week 1-2)

**Set up your development environment**

- Install Python 3.9+ with virtual environment (venv or conda)
- Install core libraries: Flask/FastAPI (for reverse proxy), scikit-learn, pandas, numpy, requests
- Set up vulnerable API backends: crAPI, VAmpi, or DVWA for testing[^1_4][^1_5]
- Install testing tools: Postman, Burp Suite Community Edition

**Understand the architecture**

- Your module acts as a reverse proxy (sits between client and API backend)
- Traffic flow: Client → Your AI/ML Security Module → Backend API → Response back through your module
- Decision point: Block malicious requests before they reach the backend


### Phase 2: Data Collection \& Dataset Preparation (Week 3-4)

**Gather training datasets**

- Download CSIC 2010 dataset (web attacks including SQLi, XSS)[^1_6][^1_7][^1_8][^1_4]
- Download ATRDF 2023 dataset (modern API attacks)[^1_4][^1_6]
- Use OWASP Core Rule Set (CRS) patterns for additional attack signatures[^1_9][^1_10][^1_11]
- Collect normal traffic samples from your test APIs[^1_7]

**Feature engineering for HTTP requests**

- Extract features from HTTP requests: URL paths, query parameters, headers, body content, HTTP methods, content-type[^1_5][^1_7]
- Create character n-gram features (sequences of 3-5 characters) from request strings[^1_7]
- Encode categorical features: HTTP methods (GET, POST, PUT, DELETE), content types
- Create statistical features: request length, special character count, entropy scores[^1_8][^1_5]

**Label your dataset**

- Binary classification: Benign (0) vs Malicious (1)
- Multi-class classification: Normal, SQLi, XSS, Path Traversal, Command Injection, etc.[^1_5][^1_8][^1_7]
- Split data: 70% training, 30% testing[^1_8]


### Phase 3: Build Basic ML Models (Week 5-7)

**Start with supervised learning algorithms**

- Random Forest: Excellent for web attack detection with 99%+ accuracy[^1_5][^1_7][^1_8]
- Decision Trees: Easy to interpret and visualize decision paths[^1_8]
- K-Nearest Neighbors (KNN): Good baseline with 89% accuracy[^1_7]
- Support Vector Machines (SVM): Effective for binary classification[^1_7]

**Implementation approach**

```python
# Pseudocode structure
1. Load and preprocess dataset
2. Extract features from HTTP requests
3. Train multiple models (Random Forest, KNN, SVM)
4. Evaluate using accuracy, precision, recall, F1-score
5. Select best performing model
6. Save trained model using pickle/joblib
```

**Model evaluation metrics**

- Accuracy: Overall correctness
- Precision: Minimize false positives (legitimate requests blocked)[^1_1]
- Recall: Minimize false negatives (attacks that slip through)
- F1-Score: Balance between precision and recall[^1_5][^1_7]


### Phase 4: Integrate Reverse Proxy Logic (Week 8-9)

**Build the proxy server**

- Use Flask or FastAPI to create HTTP server
- Implement request interception: Capture incoming requests before forwarding
- Feature extraction pipeline: Convert raw HTTP request to feature vector in real-time
- Model inference: Pass features to trained ML model for threat scoring[^1_2]
- Decision logic: If threat_score > threshold → Block (return 403), else → Forward to backend

**Real-time threat scoring implementation**

- Load pre-trained ML model at startup
- For each incoming request: extract features → predict threat score → make decision[^1_12][^1_13][^1_2]
- Return custom error messages for blocked requests with reason codes

**Forward legitimate requests**

- Use requests library to forward clean traffic to backend API
- Preserve original headers, body, and parameters
- Return backend response to client


### Phase 5: Advanced Detection Techniques (Week 10-12)

**Implement anomaly detection for zero-day attacks**

- Train unsupervised models on normal traffic: Isolation Forest, One-Class SVM[^1_13][^1_12][^1_1]
- Detect deviations from baseline behavior patterns[^1_14][^1_13][^1_1]
- Flag unusual patterns even without labeled attack examples

**Add behavioral analysis**

- Track API usage patterns per user/IP: request frequency, endpoints accessed, data access patterns[^1_12][^1_13]
- Detect anomalies: unusual request rates, accessing sensitive endpoints, data exfiltration patterns[^1_13][^1_14]
- Implement rate limiting based on ML predictions[^1_12]

**Ensemble methods for improved accuracy**

- Combine multiple models: Voting classifier or stacking[^1_5]
- Use different algorithms together for better coverage
- Reduce false positives by requiring consensus[^1_1]


### Phase 6: OWASP API Top 10 Coverage (Week 13-14)

**Extend detection to cover all OWASP API Security Top 10**[^1_11][^1_15][^1_16]

- API1: Broken Object Level Authorization (BOLA) - detect unauthorized object access patterns
- API2: Broken Authentication - identify weak auth attempts, credential stuffing[^1_17][^1_12]
- API3: Broken Object Property Level Authorization - detect excessive data exposure
- API4: Unrestricted Resource Consumption - implement intelligent rate limiting[^1_12]
- API5: Broken Function Level Authorization - detect privilege escalation attempts
- API6: Unrestricted Access to Sensitive Business Flows - identify business logic abuse[^1_14]
- API7: Server-Side Request Forgery (SSRF) - detect malicious URL patterns
- API8: Security Misconfiguration - validate headers, methods, configurations
- API9: Improper Inventory Management - track API versions and deprecations
- API10: Unsafe Consumption of APIs - validate third-party API responses[^1_15]


### Phase 7: Testing \& Validation (Week 15-16)

**Comprehensive testing strategy**

- Test with crAPI/VAmpi: Send attack payloads through Postman and Burp Suite[^1_4][^1_5]
- Verify detection: SQLi, XSS, command injection, path traversal, XXE, SSRF
- Measure performance: Latency added by ML inference (should be < 100ms)
- Test false positive rate: Ensure legitimate requests pass through

**Attack simulation scenarios**

- OWASP ZAP automated scans against your protected API
- Manual penetration testing with Burp Suite Intruder
- Custom attack payloads targeting OWASP API Top 10 vulnerabilities
- Stress testing: Handle high request volumes


### Phase 8: Production-Ready Features (Week 17-18)

**Logging and monitoring**

- Log all blocked requests with threat scores, attack types, timestamps[^1_17]
- Dashboard for real-time monitoring: attack trends, blocked threats, false positives[^1_13][^1_14][^1_12]
- Integration with SIEM systems for enterprise deployment[^1_13]

**Model updates and retraining**

- Implement feedback loop: Security analysts mark false positives/negatives
- Periodic model retraining with new attack patterns[^1_1][^1_12][^1_13]
- A/B testing for model versions before production deployment

**Configuration and tuning**

- Adjustable threat score thresholds per API endpoint
- Whitelist/blacklist capabilities for IPs and patterns
- Custom rules alongside ML predictions for known critical threats


### Key Technical Recommendations

**Model selection priorities**

- Start with Random Forest for highest accuracy (99%+)[^1_7][^1_5]
- Add Isolation Forest for anomaly detection of unknown attacks[^1_1][^1_13]
- Consider neural networks (RNN/LSTM) for sequence-based attacks later[^1_13]

**Dataset quality is critical**

- Modern datasets like ATRDF 2023 include recent attack patterns[^1_6][^1_4]
- Supplement with custom data from your test environment[^1_7]
- Regularly update training data with new attack signatures[^1_1][^1_13]

**Deployment considerations**

- Use lightweight models for real-time inference (Random Forest optimal)[^1_5]
- Cache feature extraction for performance optimization
- Implement circuit breaker: If ML fails, fallback to rule-based detection


### Learning Resources Path

**Week 1-4**: Python fundamentals, HTTP protocol, REST APIs, scikit-learn basics
**Week 5-8**: Machine learning fundamentals, supervised learning, feature engineering
**Week 9-12**: Advanced ML (anomaly detection, ensemble methods), reverse proxy development
**Week 13-16**: OWASP API Security Top 10, penetration testing, threat modeling[^1_10][^1_11][^1_15]
**Week 17-18**: MLOps, monitoring, production deployment practices

### Expected Outcomes

Your final AI/ML API security module will achieve threat detection by combining supervised classification (for known attacks with 99%+ accuracy), unsupervised anomaly detection (for zero-day threats), and behavioral analysis (for business logic abuse). The reverse proxy architecture ensures all traffic is inspected before reaching vulnerable backends, providing comprehensive protection against OWASP API Top 10 vulnerabilities.[^1_16][^1_2][^1_11][^1_15][^1_14][^1_12][^1_13][^1_1][^1_5]
<span style="display:none">[^1_18][^1_19][^1_20][^1_21][^1_22][^1_23][^1_24][^1_25][^1_26][^1_27][^1_28][^1_29][^1_30][^1_31][^1_32][^1_33]</span>

<div align="center">⁂</div>

[^1_1]: https://cashmere.io/v/xBJoe9

[^1_2]: https://cashmere.io/v/RCEzmT

[^1_3]: https://cashmere.io/v/bxwan5

[^1_4]: http://arxiv.org/pdf/2405.11258.pdf

[^1_5]: https://internationalpubls.com/index.php/pmj/article/download/2938/1734/5233

[^1_6]: http://arxiv.org/pdf/2405.11247.pdf

[^1_7]: https://pmc.ncbi.nlm.nih.gov/articles/PMC12453791/

[^1_8]: https://ijrpr.com/uploads/V6ISSUE3/IJRPR40708.pdf

[^1_9]: http://arxiv.org/pdf/2308.04964.pdf

[^1_10]: https://owasp.org/www-project-machine-learning-security-top-10/

[^1_11]: https://owasp.org/www-project-api-security/

[^1_12]: https://zuplo.com/learning-center/OWASP-Cheat-Sheet-Guide

[^1_13]: https://www.algomox.com/resources/blog/forecasting_api_security_risks_with_machine_learning/

[^1_14]: https://www.traceable.ai/api-protection

[^1_15]: https://www.pynt.io/learning-hub/owasp-top-10-guide/owasp-api-top-10

[^1_16]: https://cloudsecurityalliance.org/blog/2021/05/11/understanding-the-owasp-api-security-top-10/

[^1_17]: https://owasp.org/www-chapter-sofia/assets/presentations/202410 - API security in the age of AI by Evgeni Dyulgerov.pdf

[^1_18]: https://cashmere.io/v/Cc0Vk8

[^1_19]: https://cashmere.io/v/dptR6G

[^1_20]: https://arxiv.org/pdf/2503.09334.pdf

[^1_21]: https://arxiv.org/pdf/2404.16847.pdf

[^1_22]: http://arxiv.org/pdf/2502.12863.pdf

[^1_23]: https://aclanthology.org/2023.emnlp-main.308.pdf

[^1_24]: http://arxiv.org/pdf/2307.02192.pdf

[^1_25]: https://huggingface.co/datasets/shahrukh95/OWASP-and-NVD-question-answer-dataset/viewer/default/train

[^1_26]: https://www.upwind.io/feed/detect-and-respond-to-api-threats-with-upwind

[^1_27]: https://ieeexplore.ieee.org/document/8614199/

[^1_28]: https://www.sciencedirect.com/science/article/abs/pii/S0045790625000515

[^1_29]: https://www.sciencedirect.com/science/article/pii/S2405959525001304

[^1_30]: https://www.paloaltonetworks.com/cyberpedia/ai-in-threat-detection

[^1_31]: https://www.ijcai.org/proceedings/2019/0656.pdf

[^1_32]: https://www.techrxiv.org/users/944086/articles/1328270-ai-driven-real-time-api-security-explainable-threat-detection-for-cloud-environments

[^1_33]: https://di.fc.ul.pt/~imedeiros/papers/ENASE2024_RodrigoB.pdf


---

## AI/ML Training Module Development Roadmap

Based on your WAAP architecture and the need to delegate training tasks to your junior developer, here's a detailed step-by-step roadmap specifically for the **ML training and validation module**.[^2_1]

### Dataset Acquisition \& Sources

**Primary datasets for API attack detection:**

**CSIC 2010 HTTP Dataset** - Your foundational training dataset[^2_2][^2_3][^2_4]

- Contains 36,000 normal requests and 25,000+ anomalous requests
- Includes: SQLi, XSS, buffer overflow, CRLF injection, parameter tampering, file disclosure
- Download: Available at impactcybertrust.org/dataset or Kaggle[^2_3][^2_2]
- Format: HTTP requests labeled as normal/anomalous
- Split: Training (normal only), Test (normal + malicious)

**ATRDF 2023 (API Traffic Research Dataset Framework)** - Modern API-specific attacks[^2_5][^2_6][^2_7]

- Contains 54,000 normal + 78,000 abnormal API requests/responses
- Attack types: Directory Traversal, Cookie Injection, LOG4J, RCE, Log Forging, SQLi, XSS
- 18 different API endpoints with real-world structure
- Download: GitHub repository (arielreismanc/ATRDFv1)[^2_6]
- Pre-split: 70% train, 15% test, 15% validation

**OWASP ModSecurity Core Rule Set (CRS)** - Rule-based patterns for feature engineering[^2_8][^2_9][^2_10]

- Not a dataset but attack detection rules you can extract patterns from
- Download: github.com/coreruleset/coreruleset/releases (latest v4.0.0)[^2_9]
- Use CRS regex patterns and attack signatures as supplementary features
- Covers OWASP Top 10 attack categories

**Supplementary datasets (optional):**

- CIC-IDS2017: Network intrusion dataset with web attacks[^2_11]
- WEB-IDS23: 12 million samples with 21 fine-grained labels[^2_12]


### Training Module Roadmap for Junior Developer

#### Task 1: Environment Setup (Day 1-2)

**Assignment deliverable:** Working Python environment with all libraries installed

**Steps:**

1. Install Python 3.9+ with Anaconda or virtualenv
2. Install required libraries:

```
pip install pandas numpy scikit-learn matplotlib seaborn
pip install requests urllib3 beautifulsoup4
pip install joblib pickle-mixin
pip install imbalanced-learn (for handling imbalanced data)
```

3. Create project structure:

```
/ml_training_module
├── /datasets (raw datasets)
├── /processed_data (cleaned data)
├── /models (saved trained models)
├── /scripts (training scripts)
├── /notebooks (Jupyter for exploration)
└── /logs (training logs)
```

4. Set up Jupyter Notebook for data exploration

**Validation:** Screenshot of successful library imports and folder structure

***

#### Task 2: Dataset Download \& Initial Exploration (Day 3-4)

**Assignment deliverable:** Downloaded datasets with statistical summary report

**Steps:**

1. Download CSIC 2010 from Kaggle or ImpactCyberTrust[^2_2][^2_3]
2. Download ATRDF 2023 from GitHub (arielreismanc/ATRDFv1)[^2_6]
3. Download OWASP CRS rules from github.com/coreruleset/coreruleset[^2_9]
4. Load datasets into pandas DataFrames
5. Generate statistical report:
    - Total samples (normal vs malicious)
    - Attack type distribution
    - Request length statistics
    - Missing values check
    - Sample HTTP requests (5 normal, 5 malicious)

**Code template:**

```python
import pandas as pd

# Load CSIC 2010
csic_normal = pd.read_csv('csic_normal.csv')
csic_anomalous = pd.read_csv('csic_anomalous.csv')

# Print summary
print(f"Normal requests: {len(csic_normal)}")
print(f"Malicious requests: {len(csic_anomalous)}")
print(csic_normal.describe())
```

**Validation:** PDF report with dataset statistics and sample data

***

#### Task 3: Data Preprocessing \& Cleaning (Day 5-7)

**Assignment deliverable:** Cleaned and normalized dataset ready for feature extraction

**Steps:**

1. Parse HTTP requests into components:
    - Method (GET, POST, PUT, DELETE)
    - URL path
    - Query parameters
    - Headers
    - Body content
2. Handle special characters and encoding issues[^2_3]
3. Remove duplicates
4. Balance dataset (handle class imbalance using SMOTE if needed)
5. Label encoding:
    - Binary: 0 = Benign, 1 = Malicious
    - Multi-class: Assign numerical labels to attack types (SQLi=1, XSS=2, etc.)
6. Save cleaned data to CSV

**Code template:**

```python
from urllib.parse import urlparse, parse_qs

def parse_http_request(raw_request):
    lines = raw_request.split('\n')
    method, path, protocol = lines[^2_0].split()
    parsed_url = urlparse(path)
    
    return {
        'method': method,
        'path': parsed_url.path,
        'query': parsed_url.query,
        'params': parse_qs(parsed_url.query)
    }

# Apply parsing
df['parsed'] = df['raw_request'].apply(parse_http_request)
```

**Validation:** Cleaned CSV file with parsed components + data quality report (no nulls, balanced classes)

***

#### Task 4: Feature Engineering (Day 8-12)

**Assignment deliverable:** Feature-engineered dataset with 30-50 features per request

**Steps for feature extraction:**

**Character-level features**[^2_5]

1. Request length (total characters)
2. Special character count (`, ", ', <, >, ;, etc.)
3. Numeric character ratio
4. Uppercase ratio
5. Character entropy (Shannon entropy)

**N-gram features**[^2_5]

1. Extract 3-gram, 4-gram, 5-gram character sequences
2. Use TF-IDF vectorization on n-grams
3. Select top 100 most frequent n-grams
4. Create binary features (n-gram present/absent)

**HTTP-specific features:**

1. HTTP method (one-hot encoded: GET=1, POST=2, etc.)
2. Number of query parameters
3. Query string length
4. Header count
5. Content-Type (encoded)
6. Presence of SQL keywords (SELECT, UNION, DROP, etc.)
7. Presence of XSS patterns (<script>, javascript:, onerror=)
8. Presence of path traversal patterns (../, ..\)
9. URL depth (number of / in path)
10. Suspicious file extensions (.php, .exe, .sh)

**OWASP CRS-based features**[^2_10][^2_8]

1. Count of CRS rule pattern matches
2. Binary flags for specific attack categories from CRS rules

**Code template:**

```python
from sklearn.feature_extraction.text import TfidfVectorizer
import re

def extract_features(request):
    features = {}
    
    # Basic features
    features['length'] = len(request)
    features['special_chars'] = len(re.findall(r'[<>\'";()=]', request))
    features['sql_keywords'] = len(re.findall(r'\b(SELECT|UNION|DROP|INSERT|UPDATE|DELETE)\b', request, re.I))
    features['xss_patterns'] = len(re.findall(r'(<script|javascript:|onerror=)', request, re.I))
    
    # Add more features...
    return features

# Apply feature extraction
df['features'] = df['request'].apply(extract_features)
```

**Validation:** Feature matrix CSV with 30-50 columns + feature importance analysis

***

#### Task 5: Model Training - Baseline Models (Day 13-16)

**Assignment deliverable:** 4 trained baseline models with performance metrics

**Train these models sequentially:**

**Model 1: Random Forest Classifier**[^2_7][^2_5]

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train Random Forest
rf_model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42)
rf_model.fit(X_train, y_train)

# Predict and evaluate
y_pred = rf_model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
print(f"Precision: {precision_score(y_test, y_pred)}")
print(f"Recall: {recall_score(y_test, y_pred)}")
print(f"F1-Score: {f1_score(y_test, y_pred)}")

# Save model
import joblib
joblib.dump(rf_model, 'models/random_forest.pkl')
```

**Model 2: Decision Tree**

```python
from sklearn.tree import DecisionTreeClassifier

dt_model = DecisionTreeClassifier(max_depth=15, random_state=42)
dt_model.fit(X_train, y_train)
# Evaluate and save...
```

**Model 3: K-Nearest Neighbors (KNN)**

```python
from sklearn.neighbors import KNeighborsClassifier

knn_model = KNeighborsClassifier(n_neighbors=5)
knn_model.fit(X_train, y_train)
# Evaluate and save...
```

**Model 4: Support Vector Machine (SVM)**

```python
from sklearn.svm import SVC

svm_model = SVC(kernel='rbf', C=1.0, random_state=42)
svm_model.fit(X_train, y_train)
# Evaluate and save...
```

**Task requirements:**

- Train all 4 models on CSIC 2010 dataset
- Generate confusion matrix for each model
- Create comparison table of metrics
- Select best performing model (likely Random Forest with 99%+ accuracy)[^2_5]

**Validation:** 4 saved .pkl model files + performance comparison PDF report

***

#### Task 6: Model Training - Multi-Class Classification (Day 17-19)

**Assignment deliverable:** Multi-class model detecting specific attack types

**Steps:**

1. Use ATRDF 2023 dataset with attack type labels[^2_6][^2_5]
2. Modify labels: Normal=0, SQLi=1, XSS=2, DT=3, CI=4, RCE=5, Log4J=6, LF=7
3. Train Random Forest with multi-class support:
```python
# Multi-class Random Forest
rf_multiclass = RandomForestClassifier(n_estimators=150, max_depth=25, random_state=42)
rf_multiclass.fit(X_train, y_train_multiclass)

# Evaluate per-class metrics
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred, target_names=['Normal', 'SQLi', 'XSS', 'DT', 'CI', 'RCE', 'Log4J', 'LF']))
```

4. Analyze per-attack-type accuracy
5. Save multi-class model

**Validation:** Multi-class model .pkl file + classification report showing per-attack accuracy

***

#### Task 7: Anomaly Detection Model (Day 20-22)

**Assignment deliverable:** Unsupervised anomaly detection model for zero-day attacks

**Train Isolation Forest:**

```python
from sklearn.ensemble import IsolationForest

# Train only on normal traffic
X_normal = X[y == 0]

iso_forest = IsolationForest(contamination=0.1, random_state=42)
iso_forest.fit(X_normal)

# Test on combined normal + malicious
anomaly_scores = iso_forest.predict(X_test)
# -1 = anomaly, 1 = normal

# Evaluate
from sklearn.metrics import accuracy_score
# Convert labels: -1 to 1 (malicious), 1 to 0 (normal)
predictions = [1 if score == -1 else 0 for score in anomaly_scores]
print(f"Anomaly Detection Accuracy: {accuracy_score(y_test, predictions)}")

joblib.dump(iso_forest, 'models/isolation_forest.pkl')
```

**Alternative: One-Class SVM**

```python
from sklearn.svm import OneClassSVM

oc_svm = OneClassSVM(kernel='rbf', gamma='auto', nu=0.1)
oc_svm.fit(X_normal)
```

**Validation:** Anomaly detection model .pkl file + evaluation report

***

#### Task 8: Hyperparameter Tuning (Day 23-25)

**Assignment deliverable:** Optimized models with best hyperparameters

**Use GridSearchCV for tuning:**

```python
from sklearn.model_selection import GridSearchCV

# Random Forest hyperparameter grid
param_grid = {
    'n_estimators': [100, 150, 200],
    'max_depth': [15, 20, 25, None],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4]
}

grid_search = GridSearchCV(
    RandomForestClassifier(random_state=42),
    param_grid,
    cv=5,
    scoring='f1',
    n_jobs=-1
)

grid_search.fit(X_train, y_train)
best_model = grid_search.best_estimator_
print(f"Best parameters: {grid_search.best_params_}")
print(f"Best F1 score: {grid_search.best_score_}")

joblib.dump(best_model, 'models/random_forest_optimized.pkl')
```

**Validation:** Optimized models with hyperparameter tuning report

***

#### Task 9: Cross-Dataset Validation (Day 26-28)

**Assignment deliverable:** Model performance tested across multiple datasets

**Steps:**

1. Train model on CSIC 2010, test on ATRDF 2023
2. Train model on ATRDF 2023, test on CSIC 2010
3. Evaluate cross-dataset generalization
4. Identify dataset-specific overfitting issues
```python
# Train on CSIC, test on ATRDF
model_csic = RandomForestClassifier(n_estimators=100)
model_csic.fit(X_train_csic, y_train_csic)

y_pred_atrdf = model_csic.predict(X_test_atrdf)
cross_accuracy = accuracy_score(y_test_atrdf, y_pred_atrdf)
print(f"Cross-dataset accuracy: {cross_accuracy}")
```

**Validation:** Cross-validation report with performance metrics

***

#### Task 10: Model Ensemble \& Final Selection (Day 29-30)

**Assignment deliverable:** Final production-ready ensemble model

**Create voting classifier:**

```python
from sklearn.ensemble import VotingClassifier

# Combine best models
voting_clf = VotingClassifier(
    estimators=[
        ('rf', best_rf_model),
        ('knn', best_knn_model),
        ('svm', best_svm_model)
    ],
    voting='hard'  # or 'soft' for probability-based voting
)

voting_clf.fit(X_train, y_train)
joblib.dump(voting_clf, 'models/ensemble_model.pkl')
```

**Model selection criteria:**

- Highest F1-score (balance precision/recall)
- Lowest inference latency (< 100ms per request)
- Lowest false positive rate (avoid blocking legitimate traffic)
- Best cross-dataset generalization

**Validation:** Final model .pkl file + comprehensive performance report comparing all models

***

#### Task 11: Model Inference Pipeline (Day 31-33)

**Assignment deliverable:** Real-time inference script for integration with reverse proxy

**Create inference module:**

```python
import joblib
import numpy as np

class ThreatDetector:
    def __init__(self, model_path='models/ensemble_model.pkl'):
        self.model = joblib.load(model_path)
    
    def extract_features(self, http_request):
        # Same feature extraction as training
        features = {}
        # ... extract all features
        return np.array(list(features.values())).reshape(1, -1)
    
    def predict_threat(self, http_request):
        features = self.extract_features(http_request)
        prediction = self.model.predict(features)[^2_0]
        probability = self.model.predict_proba(features)[^2_0]
        
        return {
            'is_malicious': bool(prediction),
            'confidence': max(probability),
            'threat_score': probability[^2_1] if len(probability) > 1 else 0.0
        }

# Usage in reverse proxy
detector = ThreatDetector()
result = detector.predict_threat(incoming_request)
if result['is_malicious'] and result['confidence'] > 0.85:
    block_request()
```

**Validation:** Working inference script with < 100ms prediction time

***

#### Task 12: Testing \& Documentation (Day 34-35)

**Assignment deliverable:** Complete documentation and test results

**Create comprehensive documentation:**

1. **Training documentation:**
    - Dataset sources and preprocessing steps
    - Feature engineering methodology
    - Model architectures and hyperparameters
    - Training metrics and evaluation results
2. **Inference documentation:**
    - How to load models
    - API for prediction
    - Input/output formats
    - Performance benchmarks
3. **Model performance report:**
    - Accuracy, precision, recall, F1-score for each model
    - Confusion matrices
    - ROC curves and AUC scores
    - False positive/negative analysis
    - Inference latency measurements
4. **Integration guide:**
    - How to integrate with your reverse proxy module
    - API endpoints for threat detection
    - Configuration parameters
    - Troubleshooting guide

**Create test suite:**

```python
import unittest

class TestThreatDetector(unittest.TestCase):
    def setUp(self):
        self.detector = ThreatDetector()
    
    def test_detect_sqli(self):
        malicious_request = "GET /user?id=1' OR '1'='1"
        result = self.detector.predict_threat(malicious_request)
        self.assertTrue(result['is_malicious'])
    
    def test_normal_request(self):
        normal_request = "GET /api/users/123"
        result = self.detector.predict_threat(normal_request)
        self.assertFalse(result['is_malicious'])
```

**Validation:** Complete documentation PDF + passing test suite

***

### Final Deliverables Checklist

Your junior should provide:

1. **Models folder containing:**
    - random_forest.pkl (binary classifier)
    - decision_tree.pkl
    - knn.pkl
    - svm.pkl
    - isolation_forest.pkl (anomaly detector)
    - rf_multiclass.pkl (attack type classifier)
    - ensemble_model.pkl (final production model)
2. **Processed datasets:**
    - csic_processed.csv
    - atrdf_processed.csv
    - feature_matrix.csv
3. **Scripts:**
    - data_preprocessing.py
    - feature_extraction.py
    - train_models.py
    - inference.py
    - test_inference.py
4. **Documentation:**
    - training_methodology.pdf
    - model_performance_report.pdf
    - integration_guide.pdf
    - api_documentation.pdf
5. **Performance metrics:**
    - Model comparison spreadsheet
    - Confusion matrices (images)
    - ROC curves (images)
    - Cross-validation results

### Integration with Your Reverse Proxy

Once training is complete, integrate the inference module into your reverse proxy:

```python
from flask import Flask, request, jsonify
from threat_detector import ThreatDetector
import requests

app = Flask(__name__)
detector = ThreatDetector('models/ensemble_model.pkl')

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    # Extract incoming request
    raw_request = f"{request.method} {request.full_path}"
    
    # Threat detection
    threat_result = detector.predict_threat(raw_request)
    
    # Block malicious requests
    if threat_result['is_malicious'] and threat_result['confidence'] > 0.85:
        return jsonify({
            'error': 'Request blocked',
            'reason': 'Malicious pattern detected',
            'threat_score': threat_result['threat_score']
        }), 403
    
    # Forward legitimate requests to backend
    backend_url = f"http://backend-api:8080/{path}"
    response = requests.request(
        method=request.method,
        url=backend_url,
        headers=dict(request.headers),
        data=request.get_data()
    )
    
    return response.content, response.status_code
```


### Expected Timeline

**Total duration:** 35 days (approximately 5 weeks) for a beginner

- **Week 1:** Setup, data acquisition, preprocessing (Tasks 1-3)
- **Week 2:** Feature engineering (Task 4)
- **Week 3:** Baseline model training (Tasks 5-6)
- **Week 4:** Advanced models and optimization (Tasks 7-9)
- **Week 5:** Final integration and documentation (Tasks 10-12)

This roadmap provides your junior developer with clear, actionable tasks and validation criteria for each step, ensuring the ML training module integrates seamlessly with your WAAP reverse proxy architecture.[^2_8][^2_7][^2_10][^2_2][^2_3][^2_9][^2_6][^2_5]
<span style="display:none">[^2_13][^2_14][^2_15][^2_16][^2_17][^2_18][^2_19][^2_20][^2_21][^2_22][^2_23][^2_24][^2_25][^2_26][^2_27][^2_28][^2_29]</span>

<div align="center">⁂</div>

[^2_1]: https://cashmere.io/v/xBJoe9

[^2_2]: https://www.kaggle.com/datasets/ispangler/csic-2010-web-application-attacks

[^2_3]: https://www.impactcybertrust.org/dataset_view?idDataset=940

[^2_4]: https://petescully.co.uk/wp-content/uploads/2018/04/http_dataset_csic_2010.pdf

[^2_5]: https://arxiv.org/html/2405.11258v1

[^2_6]: https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge

[^2_7]: https://arxiv.org/html/2405.11247v1

[^2_8]: https://github.com/coreruleset/coreruleset

[^2_9]: https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/

[^2_10]: https://owasp.org/www-project-modsecurity-core-rule-set/

[^2_11]: https://www.unb.ca/cic/datasets/ids-2017.html

[^2_12]: https://arxiv.org/pdf/2502.03909.pdf

[^2_13]: https://www.mdpi.com/1424-8220/23/13/5941/pdf?version=1687924880

[^2_14]: https://arxiv.org/pdf/2310.10661.pdf

[^2_15]: https://linkinghub.elsevier.com/retrieve/pii/S2352340920311987

[^2_16]: https://linkinghub.elsevier.com/retrieve/pii/S0167404822004436

[^2_17]: https://arxiv.org/pdf/2307.11544.pdf

[^2_18]: https://www.mdpi.com/2079-9292/9/5/800/pdf

[^2_19]: https://pmc.ncbi.nlm.nih.gov/articles/PMC10346235/

[^2_20]: https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/tree/master/csic_2010

[^2_21]: https://github.com/msudol/Web-Application-Attack-Datasets

[^2_22]: https://www.kaggle.com/general/335189

[^2_23]: https://www.netnea.com/cms/apache-tutorial-7_including-modsecurity-core-rules/

[^2_24]: https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1016

[^2_25]: https://www.sciencedirect.com/science/article/abs/pii/S0167404824005558

[^2_26]: https://ieeexplore.ieee.org/iel8/11036321/11036274/11036344.pdf

[^2_27]: https://coreruleset.org

[^2_28]: https://papers.ssrn.com/sol3/papers.cfm?abstract_id=4927579

[^2_29]: https://modsecurity.org

