import streamlit as st
import pandas as pd
import numpy as np
import re
import warnings
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
from sklearn.metrics import precision_recall_curve, average_precision_score
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import time

# Suppress warnings
warnings.filterwarnings('ignore')

# Set page config
st.set_page_config(
    page_title="🛡️ SQL Injection Sanitizer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.main-header {
    font-size: 2.5rem;
    color: #2E86AB;
    text-align: center;
    margin-bottom: 2rem;
    font-weight: bold;
}
.sub-header {
    font-size: 1.5rem;
    color: #2C3E50;
    margin: 1rem 0;
    font-weight: 600;
}
.metric-card {
    background-color: #F8F9FA;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #2E86AB;
    margin: 0.5rem 0;
}
.safe-result {
    background-color: #D4EDDA;
    color: #155724;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #28A745;
}
.danger-result {
    background-color: #F8D7DA;
    color: #721C24;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #DC3545;
}
.warning-result {
    background-color: #FFF3CD;
    color: #856404;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #FFC107;
}
</style>
""", unsafe_allow_html=True)

class RuleBasedSQLDetector:
    """Rule-based SQL injection detector using regex patterns"""
    
    def __init__(self):
        # Define comprehensive SQL injection patterns
        self.patterns = {
            'tautology': [
                r"\s*(or|OR)\s+['\"]?\d*['\"]?\s*=\s*['\"]?\d*['\"]?",  # OR 1=1
                r"\s*(or|OR)\s+['\"]?[a-zA-Z]*['\"]?\s*=\s*['\"]?[a-zA-Z]*['\"]?",  # OR 'x'='x'
            ],
            'union_attack': [
                r"\s*(union|UNION)\s+(select|SELECT)",  # UNION SELECT
                r"\s*(union|UNION)\s+(all|ALL)\s+(select|SELECT)",  # UNION ALL SELECT
            ],
            'comment_injection': [
                r"--",  # SQL comment
                r"/\*.*\*/",  # Multi-line comment
                r"#",  # MySQL comment
            ],
            'stacked_queries': [
                r";\s*(drop|DROP)\s+(table|TABLE)",  # DROP TABLE
                r";\s*(delete|DELETE)\s+(from|FROM)",  # DELETE FROM
                r";\s*(insert|INSERT)\s+(into|INTO)",  # INSERT INTO
                r";\s*(update|UPDATE)\s+",  # UPDATE
                r";\s*(exec|EXEC|execute|EXECUTE)",  # EXEC
                r";\s*(create|CREATE)\s+(table|TABLE)",  # CREATE TABLE
                r";\s*(truncate|TRUNCATE)\s+(table|TABLE)",  # TRUNCATE TABLE
            ],
            'time_based': [
                r"(sleep|SLEEP)\s*\(",  # SLEEP function
                r"(waitfor|WAITFOR)\s+(delay|DELAY)",  # WAITFOR DELAY
                r"(pg_sleep|PG_SLEEP)\s*\(",  # PostgreSQL sleep
                r"(benchmark|BENCHMARK)\s*\(",  # MySQL BENCHMARK
            ],
            'information_gathering': [
                r"(@@version|@@VERSION)",  # Version information
                r"(information_schema|INFORMATION_SCHEMA)",  # Schema information
                r"(table_name|TABLE_NAME)",  # Table names
                r"(column_name|COLUMN_NAME)",  # Column names
                r"(database|DATABASE)\s*\(\s*\)",  # DATABASE function
                r"(user|USER)\s*\(\s*\)",  # USER function
            ],
            'dangerous_functions': [
                r"(xp_cmdshell|XP_CMDSHELL)",  # Command execution
                r"(sp_|SP_)[a-zA-Z_]+",  # Stored procedures
                r"(load_file|LOAD_FILE)",  # File operations
                r"(into\s+outfile|INTO\s+OUTFILE)",  # File writing
                r"(extractvalue|EXTRACTVALUE)",  # XML extraction
                r"(updatexml|UPDATEXML)",  # XML update
            ]
        }
        
        # Compile patterns for efficiency
        self.compiled_patterns = {}
        for category, pattern_list in self.patterns.items():
            self.compiled_patterns[category] = [re.compile(p, re.IGNORECASE) for p in pattern_list]
    
    def detect_injection(self, query):
        """Detect SQL injection attempts and return detailed results"""
        results = {
            'is_malicious': False,
            'detected_patterns': [],
            'risk_score': 0,
            'highlighted_query': query
        }
        
        total_matches = 0
        
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(query)
                if matches:
                    results['detected_patterns'].append({
                        'category': category,
                        'pattern': pattern.pattern,
                        'matches': matches
                    })
                    total_matches += len(matches)
        
        # Calculate risk score (0-100)
        results['risk_score'] = min(total_matches * 25, 100)
        results['is_malicious'] = results['risk_score'] > 20
        
        # Highlight dangerous parts
        results['highlighted_query'] = self._highlight_dangerous_parts(query)
        
        return results
    
    def _highlight_dangerous_parts(self, query):
        """Highlight dangerous parts of the query using HTML markup"""
        highlighted = query
        
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                highlighted = pattern.sub(
                    r'<span style="background-color: #ffcccc; font-weight: bold; color: #721c24;">\g<0></span>',
                    highlighted
                )
        
        return highlighted
    
    def sanitize_input(self, query):
        """Basic sanitization by removing/escaping dangerous characters"""
        sanitized = query
        
        # Remove SQL comments
        sanitized = re.sub(r'--.*$', '', sanitized, flags=re.MULTILINE)
        sanitized = re.sub(r'/\*.*?\*/', '', sanitized, flags=re.DOTALL)
        sanitized = re.sub(r'#.*$', '', sanitized, flags=re.MULTILINE)
        
        # Escape single quotes
        sanitized = sanitized.replace("'", "''")
        
        # Remove semicolons (prevent stacked queries)
        sanitized = sanitized.replace(';', '')
        
        # Remove dangerous keywords
        dangerous_keywords = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'EXEC', 'EXECUTE', 'UNION', 'CREATE', 'TRUNCATE']
        for keyword in dangerous_keywords:
            pattern = re.compile(r'\b' + keyword + r'\b', re.IGNORECASE)
            sanitized = pattern.sub('[REMOVED]', sanitized)
        
        return sanitized.strip()

class MLSQLDetector:
    """Machine Learning-based SQL injection detector"""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            analyzer='char',
            lowercase=True,
            token_pattern=r'\S+'
        )
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10
        )
        self.lr_model = LogisticRegression(
            random_state=42,
            max_iter=1000
        )
        self.is_trained = False
    
    def train(self, X, y):
        """Train the ML models on the provided data"""
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        # Vectorize the text data
        X_train_tfidf = self.vectorizer.fit_transform(X_train)
        X_test_tfidf = self.vectorizer.transform(X_test)
        
        # Train Random Forest
        self.rf_model.fit(X_train_tfidf, y_train)
        
        # Train Logistic Regression
        self.lr_model.fit(X_train_tfidf, y_train)
        
        # Evaluate models
        rf_score = self.rf_model.score(X_test_tfidf, y_test)
        lr_score = self.lr_model.score(X_test_tfidf, y_test)
        
        self.is_trained = True
        
        # Store test data for visualization
        self.X_test = X_test
        self.y_test = y_test
        self.X_test_tfidf = X_test_tfidf
        
        return {
            'rf_accuracy': rf_score,
            'lr_accuracy': lr_score,
            'X_test': X_test,
            'y_test': y_test
        }
    
    def predict(self, query):
        """Predict if a query is malicious using trained models"""
        if not self.is_trained:
            raise ValueError("Models must be trained before prediction!")
        
        # Vectorize the query
        query_tfidf = self.vectorizer.transform([query])
        
        # Get predictions
        rf_pred = self.rf_model.predict(query_tfidf)[0]
        rf_prob = self.rf_model.predict_proba(query_tfidf)[0][1]
        
        lr_pred = self.lr_model.predict(query_tfidf)[0]
        lr_prob = self.lr_model.predict_proba(query_tfidf)[0][1]
        
        # Ensemble prediction (average probabilities)
        ensemble_prob = (rf_prob + lr_prob) / 2
        ensemble_pred = 1 if ensemble_prob > 0.5 else 0
        
        return {
            'rf_prediction': rf_pred,
            'rf_probability': rf_prob,
            'lr_prediction': lr_pred,
            'lr_probability': lr_prob,
            'ensemble_prediction': ensemble_pred,
            'ensemble_probability': ensemble_prob
        }
    
    def get_feature_importance(self, top_n=10):
        """Get the most important features from the Random Forest model"""
        if not self.is_trained:
            return None
        
        feature_names = self.vectorizer.get_feature_names_out()
        importances = self.rf_model.feature_importances_
        
        # Get top features
        top_indices = importances.argsort()[-top_n:][::-1]
        top_features = [(feature_names[i], importances[i]) for i in top_indices]
        
        return top_features

class ComprehensiveSQLSanitizer:
    """Comprehensive SQL injection sanitization system"""
    
    def __init__(self, rule_detector, ml_detector):
        self.rule_detector = rule_detector
        self.ml_detector = ml_detector
    
    def analyze_input(self, query, use_ml=True):
        """Comprehensive analysis of input query using both rule-based and ML methods"""
        # Rule-based analysis
        rule_result = self.rule_detector.detect_injection(query)
        
        # ML-based analysis (if available and requested)
        ml_result = None
        if use_ml and self.ml_detector.is_trained:
            try:
                ml_result = self.ml_detector.predict(query)
            except:
                ml_result = None
        
        # Combined risk assessment
        combined_risk = self._calculate_combined_risk(rule_result, ml_result)
        
        # Generate sanitized version
        sanitized_query = self.rule_detector.sanitize_input(query)
        
        return {
            'original_query': query,
            'rule_based_result': rule_result,
            'ml_result': ml_result,
            'combined_risk': combined_risk,
            'sanitized_query': sanitized_query,
            'recommendation': self._get_recommendation(combined_risk)
        }
    
    def _calculate_combined_risk(self, rule_result, ml_result):
        """Calculate combined risk score from rule-based and ML results"""
        rule_risk = rule_result['risk_score']
        
        if ml_result:
            ml_risk = ml_result['ensemble_probability'] * 100
            # Weighted combination (60% rule-based, 40% ML)
            combined = (rule_risk * 0.6) + (ml_risk * 0.4)
        else:
            combined = rule_risk
        
        return min(combined, 100)
    
    def _get_recommendation(self, risk_score):
        """Get security recommendation based on risk score"""
        if risk_score < 20:
            return "✅ LOW RISK: Query appears safe"
        elif risk_score < 50:
            return "⚠️ MEDIUM RISK: Query contains suspicious patterns"
        elif risk_score < 80:
            return "❌ HIGH RISK: Likely SQL injection attempt"
        else:
            return "🚨 CRITICAL RISK: Definite SQL injection attack"

@st.cache_data
def create_sample_dataset():
    """Create a sample dataset for training"""
    # Legitimate SQL queries
    safe_queries = [
        "SELECT * FROM users WHERE id = 1",
        "SELECT name, email FROM customers WHERE age > 18",
        "INSERT INTO products (name, price) VALUES ('laptop', 999.99)",
        "UPDATE users SET last_login = NOW() WHERE id = 123",
        "SELECT COUNT(*) FROM orders WHERE date >= '2023-01-01'",
        "SELECT product_name FROM inventory WHERE quantity > 0",
        "INSERT INTO logs (timestamp, message) VALUES (NOW(), 'User logged in')",
        "DELETE FROM temp_files WHERE created_date < '2023-01-01'",
        "SELECT * FROM articles WHERE published = 1 ORDER BY date DESC",
        "UPDATE settings SET value = 'enabled' WHERE setting_name = 'notifications'",
        "SELECT u.name, p.title FROM users u JOIN posts p ON u.id = p.user_id",
        "INSERT INTO comments (post_id, content) VALUES (1, 'Great article!')",
        "SELECT AVG(rating) FROM reviews WHERE product_id = 5",
        "UPDATE inventory SET quantity = quantity - 1 WHERE product_id = 10",
        "SELECT * FROM events WHERE event_date BETWEEN '2023-01-01' AND '2023-12-31'",
        "SELECT * FROM customers WHERE city = 'New York'",
        "INSERT INTO orders (customer_id, total) VALUES (123, 49.99)",
        "SELECT product_name, price FROM catalog WHERE category = 'electronics'",
        "UPDATE profiles SET bio = 'Software developer' WHERE user_id = 456",
        "SELECT * FROM transactions WHERE amount > 100 AND status = 'completed'"
    ]
    
    # SQL injection attack patterns
    malicious_queries = [
        # Tautology attacks
        "' OR '1'='1",
        "' OR 1=1 --",
        "admin' OR '1'='1' --",
        "' OR 'x'='x",
        "1' OR '1'='1' /*",
        "' OR 'a'='a",
        "1' OR 1=1 #",
        
        # Union-based attacks
        "' UNION SELECT * FROM admin_users --",
        "' UNION SELECT username, password FROM users --",
        "1' UNION SELECT null, @@version --",
        "' UNION ALL SELECT table_name FROM information_schema.tables --",
        "' UNION SELECT 1,2,3,4 --",
        "' UNION SELECT user(), database(), version() --",
        "1' UNION SELECT null, concat(username,':',password) FROM users --",
        
        # Comment-based attacks
        "admin'--",
        "user'; --",
        "' OR 1=1 #",
        "admin' /*",
        "test'/**/OR/**/1=1--",
        
        # Stacked queries
        "'; DROP TABLE users; --",
        "1; DELETE FROM products; --",
        "'; INSERT INTO admin (user) VALUES ('hacker'); --",
        "1; UPDATE users SET password = 'hacked' WHERE id = 1; --",
        "'; EXEC xp_cmdshell('dir'); --",
        "'; CREATE TABLE backdoor (id INT); --",
        "1; TRUNCATE TABLE logs; --",
        
        # Time-based blind injection
        "' OR SLEEP(5) --",
        "'; WAITFOR DELAY '0:0:5' --",
        "' OR pg_sleep(5) --",
        "1' AND (SELECT SLEEP(5)) --",
        "' OR BENCHMARK(1000000,MD5(1)) --",
        
        # Boolean-based blind injection
        "1' AND (SELECT COUNT(*) FROM users) > 0 --",
        "' OR EXISTS(SELECT * FROM users WHERE username = 'admin') --",
        "1' AND LENGTH(database()) > 5 --",
        "' AND (SELECT SUBSTRING(@@version,1,1)) = '5' --",
        "1' AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1)) > 65 --",
        
        # Error-based injection
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
        "' AND (SELECT * FROM (SELECT COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) --",
        "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT @@version), 0x7e), 1) --",
        
        # Additional complex patterns
        "1' OR 1=1 AND 'admin'='admin",
        "'; CREATE TABLE hacked (id INT); --",
        "' OR 1=1 LIMIT 1 --",
        "admin' OR 1=1 UNION SELECT null --",
        "' AND 1=CONVERT(int, (SELECT @@version)) --",
        "1' OR 1=1 INTO OUTFILE '/tmp/hack' --",
        "' OR 1=1 GROUP BY password HAVING 1=1 --"
    ]
    
    # Create DataFrame
    queries = safe_queries + malicious_queries
    labels = [0] * len(safe_queries) + [1] * len(malicious_queries)
    
    df = pd.DataFrame({
        'Query': queries,
        'Label': labels,
        'Length': [len(q) for q in queries]
    })
    
    return df

@st.cache_resource
def initialize_models():
    """Initialize and train the models"""
    # Create dataset
    df = create_sample_dataset()
    
    # Initialize detectors
    rule_detector = RuleBasedSQLDetector()
    ml_detector = MLSQLDetector()
    
    # Train ML models
    with st.spinner("Training machine learning models..."):
        training_results = ml_detector.train(df['Query'], df['Label'])
    
    # Initialize sanitizer
    sanitizer = ComprehensiveSQLSanitizer(rule_detector, ml_detector)
    
    return rule_detector, ml_detector, sanitizer, df, training_results

def create_plotly_visualizations(ml_detector, rule_detector, df):
    """Create interactive Plotly visualizations"""
    
    # 1. Dataset Distribution
    safe_count = sum(df['Label'] == 0)
    malicious_count = sum(df['Label'] == 1)
    
    fig_dist = go.Figure(data=[go.Pie(
        labels=['Safe Queries', 'Malicious Queries'],
        values=[safe_count, malicious_count],
        hole=0.3,
        marker_colors=['#2ECC71', '#E74C3C']
    )])
    fig_dist.update_layout(
        title="Dataset Distribution",
        font=dict(size=14),
        height=400
    )
    
    # 2. Query Length Distribution
    safe_lengths = df[df['Label'] == 0]['Length']
    malicious_lengths = df[df['Label'] == 1]['Length']
    
    fig_length = go.Figure()
    fig_length.add_trace(go.Histogram(
        x=safe_lengths,
        name='Safe Queries',
        marker_color='#2ECC71',
        opacity=0.7,
        nbinsx=20
    ))
    fig_length.add_trace(go.Histogram(
        x=malicious_lengths,
        name='Malicious Queries',
        marker_color='#E74C3C',
        opacity=0.7,
        nbinsx=20
    ))
    fig_length.update_layout(
        title="Query Length Distribution",
        xaxis_title="Query Length (characters)",
        yaxis_title="Count",
        barmode='overlay',
        height=400
    )
    
    # 3. Model Performance (if trained)
    if ml_detector.is_trained:
        X_test_tfidf = ml_detector.X_test_tfidf
        y_test = ml_detector.y_test
        
        rf_accuracy = ml_detector.rf_model.score(X_test_tfidf, y_test)
        lr_accuracy = ml_detector.lr_model.score(X_test_tfidf, y_test)
        
        fig_performance = go.Figure()
        fig_performance.add_trace(go.Bar(
            x=['Random Forest', 'Logistic Regression'],
            y=[rf_accuracy, lr_accuracy],
            marker_color=['#3498DB', '#F39C12'],
            text=[f'{rf_accuracy:.3f}', f'{lr_accuracy:.3f}'],
            textposition='auto'
        ))
        fig_performance.update_layout(
            title="Model Accuracy Comparison",
            yaxis_title="Accuracy",
            height=400,
            yaxis=dict(range=[0, 1.1])
        )
        
        # 4. ROC Curves
        rf_proba = ml_detector.rf_model.predict_proba(X_test_tfidf)[:, 1]
        lr_proba = ml_detector.lr_model.predict_proba(X_test_tfidf)[:, 1]
        
        from sklearn.metrics import roc_curve, auc
        fpr_rf, tpr_rf, _ = roc_curve(y_test, rf_proba)
        fpr_lr, tpr_lr, _ = roc_curve(y_test, lr_proba)
        
        auc_rf = auc(fpr_rf, tpr_rf)
        auc_lr = auc(fpr_lr, tpr_lr)
        
        fig_roc = go.Figure()
        fig_roc.add_trace(go.Scatter(
            x=fpr_rf, y=tpr_rf,
            mode='lines',
            name=f'Random Forest (AUC = {auc_rf:.3f})',
            line=dict(color='#3498DB', width=2)
        ))
        fig_roc.add_trace(go.Scatter(
            x=fpr_lr, y=tpr_lr,
            mode='lines',
            name=f'Logistic Regression (AUC = {auc_lr:.3f})',
            line=dict(color='#F39C12', width=2)
        ))
        fig_roc.add_trace(go.Scatter(
            x=[0, 1], y=[0, 1],
            mode='lines',
            name='Random',
            line=dict(color='gray', width=1, dash='dash')
        ))
        fig_roc.update_layout(
            title="ROC Curves",
            xaxis_title="False Positive Rate",
            yaxis_title="True Positive Rate",
            height=400
        )
        
        return fig_dist, fig_length, fig_performance, fig_roc
    
    return fig_dist, fig_length, None, None

def main():
    """Main Streamlit application"""
    
    # Title
    st.markdown('<h1 class="main-header">🛡️ SQL Injection Detection & Sanitization System</h1>', 
                unsafe_allow_html=True)
    
    # Initialize models
    rule_detector, ml_detector, sanitizer, df, training_results = initialize_models()
    
    # Sidebar
    st.sidebar.title("🎛️ Control Panel")
    
    # Model toggle
    use_ml = st.sidebar.checkbox("Use Machine Learning Detection", value=True, 
                                help="Toggle to enable/disable ML-based detection")
    
    # Sample queries
    sample_queries = {
        "Safe Query - Select": "SELECT * FROM users WHERE id = 1",
        "Safe Query - Insert": "INSERT INTO products (name, price) VALUES ('laptop', 999.99)",
        "Safe Query - Update": "UPDATE users SET last_login = NOW() WHERE id = 123",
        "Tautology Attack": "' OR '1'='1",
        "Union Attack": "' UNION SELECT username, password FROM users --",
        "Drop Table Attack": "'; DROP TABLE users; --",
        "Comment Injection": "admin'--",
        "Time-based Attack": "' OR SLEEP(5) --",
        "Stacked Query Attack": "1; DELETE FROM products; --",
        "Information Gathering": "1' UNION SELECT null, @@version --"
    }
    
    selected_sample = st.sidebar.selectbox(
        "📋 Sample Queries",
        options=list(sample_queries.keys()),
        help="Select a predefined query to test"
    )
    
    # Main content area
    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Query Analyzer", "📊 Dashboard", "📈 Model Performance", "🛡️ Security Guide"])
    
    with tab1:
        st.markdown('<h2 class="sub-header">SQL Query Analysis</h2>', unsafe_allow_html=True)
        
        # Input section
        col1, col2 = st.columns([3, 1])
        
        with col1:
            # Text input for SQL query
            query_input = st.text_area(
                "Enter SQL Query:",
                value=sample_queries[selected_sample],
                height=100,
                help="Enter your SQL query here or select from sample queries"
            )
        
        with col2:
            st.markdown("### Quick Actions")
            if st.button("🔍 Analyze Query", type="primary"):
                if query_input.strip():
                    # Perform analysis
                    with st.spinner("Analyzing query..."):
                        result = sanitizer.analyze_input(query_input.strip(), use_ml=use_ml)
                        time.sleep(0.5)  # Add small delay for effect
                    
                    # Display results
                    st.success("Analysis completed!")
                    
                    # Risk assessment
                    risk_score = result['combined_risk']
                    if risk_score < 20:
                        st.markdown(f'<div class="safe-result">✅ <strong>LOW RISK</strong> - Risk Score: {risk_score:.1f}/100<br>Query appears safe to execute.</div>', unsafe_allow_html=True)
                    elif risk_score < 50:
                        st.markdown(f'<div class="warning-result">⚠️ <strong>MEDIUM RISK</strong> - Risk Score: {risk_score:.1f}/100<br>Query contains suspicious patterns.</div>', unsafe_allow_html=True)
                    elif risk_score < 80:
                        st.markdown(f'<div class="danger-result">❌ <strong>HIGH RISK</strong> - Risk Score: {risk_score:.1f}/100<br>Likely SQL injection attempt.</div>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div class="danger-result">🚨 <strong>CRITICAL RISK</strong> - Risk Score: {risk_score:.1f}/100<br>Definite SQL injection attack!</div>', unsafe_allow_html=True)
                    
                    # Detailed results
                    st.markdown("---")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("### 🛡️ Rule-Based Analysis")
                        rule_result = result['rule_based_result']
                        
                        st.metric(
                            label="Risk Score",
                            value=f"{rule_result['risk_score']}/100",
                            delta=f"{'Malicious' if rule_result['is_malicious'] else 'Safe'}"
                        )
                        
                        if rule_result['detected_patterns']:
                            st.markdown("**Detected Patterns:**")
                            for i, pattern in enumerate(rule_result['detected_patterns'][:3], 1):
                                category = pattern['category'].replace('_', ' ').title()
                                matches = ', '.join(pattern['matches'][:3])
                                st.write(f"{i}. **{category}**: {matches}")
                    
                    with col2:
                        if result['ml_result'] and use_ml:
                            st.markdown("### 🤖 Machine Learning Analysis")
                            ml_result = result['ml_result']
                            
                            st.metric(
                                label="Ensemble Probability",
                                value=f"{ml_result['ensemble_probability']:.3f}",
                                delta=f"{'Malicious' if ml_result['ensemble_prediction'] else 'Safe'}"
                            )
                            
                            st.write("**Model Predictions:**")
                            st.write(f"🌲 Random Forest: {ml_result['rf_probability']:.3f}")
                            st.write(f"📈 Logistic Regression: {ml_result['lr_probability']:.3f}")
                        else:
                            st.info("Enable ML detection to see machine learning analysis")
                    
                    # Query visualization
                    st.markdown("---")
                    st.markdown("### 🎨 Query Visualization")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Original Query:**")
                        st.code(result['original_query'], language='sql')
                    
                    with col2:
                        st.markdown("**Sanitized Query:**")
                        st.code(result['sanitized_query'], language='sql')
                    
                    # Highlighted query
                    st.markdown("**Highlighted Dangerous Patterns:**")
                    st.markdown(f'<div style="font-family: monospace; padding: 10px; border: 1px solid #ccc; background-color: #f9f9f9; border-radius: 5px;">{rule_result["highlighted_query"]}</div>', 
                              unsafe_allow_html=True)
                    
                else:
                    st.error("Please enter a SQL query to analyze")
            
            if st.button("🗑️ Clear"):
                st.rerun()
    
    with tab2:
        st.markdown('<h2 class="sub-header">System Dashboard</h2>', unsafe_allow_html=True)
        
        # Create visualizations
        fig_dist, fig_length, fig_performance, fig_roc = create_plotly_visualizations(ml_detector, rule_detector, df)
        
        # Display metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Queries", len(df))
        with col2:
            st.metric("Safe Queries", sum(df['Label'] == 0))
        with col3:
            st.metric("Malicious Queries", sum(df['Label'] == 1))
        with col4:
            if ml_detector.is_trained:
                avg_accuracy = (training_results['rf_accuracy'] + training_results['lr_accuracy']) / 2
                st.metric("Avg Model Accuracy", f"{avg_accuracy:.3f}")
        
        st.markdown("---")
        
        # Display visualizations
        col1, col2 = st.columns(2)
        
        with col1:
            st.plotly_chart(fig_dist, use_container_width=True)
        
        with col2:
            st.plotly_chart(fig_length, use_container_width=True)
        
        if fig_performance and fig_roc:
            col1, col2 = st.columns(2)
            
            with col1:
                st.plotly_chart(fig_performance, use_container_width=True)
            
            with col2:
                st.plotly_chart(fig_roc, use_container_width=True)
    
    with tab3:
        st.markdown('<h2 class="sub-header">Model Performance Analysis</h2>', unsafe_allow_html=True)
        
        if ml_detector.is_trained:
            # Model metrics
            st.markdown("### 📊 Training Results")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric(
                    "Random Forest Accuracy",
                    f"{training_results['rf_accuracy']:.3f}",
                    delta="Trained"
                )
            
            with col2:
                st.metric(
                    "Logistic Regression Accuracy", 
                    f"{training_results['lr_accuracy']:.3f}",
                    delta="Trained"
                )
            
            # Feature importance
            st.markdown("### 🔍 Feature Importance (Top 10)")
            
            top_features = ml_detector.get_feature_importance(top_n=10)
            if top_features:
                features_df = pd.DataFrame(top_features, columns=['Feature', 'Importance'])
                
                fig_importance = px.bar(
                    features_df,
                    x='Importance',
                    y='Feature',
                    orientation='h',
                    title="Top 10 Most Important Features"
                )
                fig_importance.update_layout(height=400)
                st.plotly_chart(fig_importance, use_container_width=True)
            
            # Classification report
            st.markdown("### 📈 Detailed Classification Metrics")
            
            from sklearn.metrics import classification_report
            X_test_tfidf = ml_detector.X_test_tfidf
            y_test = ml_detector.y_test
            
            rf_pred = ml_detector.rf_model.predict(X_test_tfidf)
            lr_pred = ml_detector.lr_model.predict(X_test_tfidf)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.text("Random Forest Classification Report:")
                rf_report = classification_report(y_test, rf_pred, target_names=['Safe', 'Malicious'])
                st.text(rf_report)
            
            with col2:
                st.text("Logistic Regression Classification Report:")
                lr_report = classification_report(y_test, lr_pred, target_names=['Safe', 'Malicious'])
                st.text(lr_report)
        
        else:
            st.warning("Models are not trained yet.")
    
    with tab4:
        st.markdown('<h2 class="sub-header">Security Best Practices</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        ### 🛡️ SQL Injection Prevention Guidelines
        
        #### 🔴 Primary Defenses (Most Critical)
        
        1. **Use Parameterized Queries/Prepared Statements**
           - This is the most effective defense against SQL injection
           - Never concatenate user input directly into SQL queries
           - Use placeholders for dynamic values
        
        2. **Input Validation**
           - Validate all user inputs against expected patterns
           - Use whitelist validation (allow only known good input)
           - Reject or sanitize suspicious input
        
        3. **Escape All User Data**
           - Properly escape special characters in dynamic queries
           - Use database-specific escaping functions
        
        #### 🟡 Additional Defenses
        
        - **Least Privilege Principle**: Limit database user permissions
        - **Regular Security Audits**: Review and test your code regularly
        - **Error Handling**: Don't expose database errors to users
        - **Web Application Firewall (WAF)**: Add an additional layer of protection
        
        #### 🔵 How This System Helps
        
        - **Rule-Based Detection**: Catches known attack patterns using regex
        - **ML-Based Detection**: Identifies novel or complex attack patterns  
        - **Risk Assessment**: Provides quantified risk scoring
        - **Input Sanitization**: Removes/escapes dangerous characters as backup
        
        #### ⚠️ Important Limitations
        
        - This system should be used as a **detection and monitoring tool**
        - Sophisticated attacks may still bypass pattern-based detection
        - Always use parameterized queries as your first line of defense
        - Sanitization can break legitimate queries - validate before sanitizing
        
        ### 📚 Code Examples
        
        **❌ Vulnerable Code:**
        ```python
        query = "SELECT * FROM users WHERE username = '" + user_input + "'"
        cursor.execute(query)
        ```
        
        **✅ Secure Code:**
        ```python
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (user_input,))
        ```
        """)
        
        # Attack examples
        st.markdown("### 🎯 Common Attack Patterns")
        
        attack_examples = {
            "Tautology Attack": {
                "example": "' OR '1'='1",
                "description": "Always evaluates to true, bypassing authentication"
            },
            "Union Attack": {
                "example": "' UNION SELECT username, password FROM users --",
                "description": "Combines malicious query with original to extract data"
            },
            "Comment Injection": {
                "example": "admin'--",
                "description": "Uses SQL comments to ignore rest of query"
            },
            "Stacked Query": {
                "example": "'; DROP TABLE users; --",
                "description": "Executes multiple SQL statements"
            },
            "Time-based Blind": {
                "example": "' OR SLEEP(5) --",
                "description": "Uses time delays to infer information"
            }
        }
        
        for attack_name, attack_info in attack_examples.items():
            with st.expander(f"🔸 {attack_name}"):
                st.code(attack_info["example"], language="sql")
                st.write(attack_info["description"])

if __name__ == "__main__":
    main()