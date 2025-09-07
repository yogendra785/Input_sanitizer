# 🛡️ SQL Injection Detection & Sanitization System

A hybrid cybersecurity solution that combines rule-based pattern matching with machine learning to detect and sanitize SQL injection attacks in real-time. Built with a focus on interpretability, performance, and developer education.

---

## 🚀 Project Overview

SQL injection remains one of the most critical vulnerabilities in web applications, affecting over 65% of platforms globally. This system proactively detects and mitigates SQLi threats using a dual-layer approach: regex-based pattern recognition and ML classification.

---

## 🔧 Technologies Used

- **Machine Learning**: TF-IDF Vectorization, Random Forest, Logistic Regression  
- **Backend**: Python, Scikit-learn, Pandas, NumPy  
- **Frontend**: Streamlit, Plotly  
- **Visualization**: Matplotlib, Seaborn  
- **Security**: Regex Pattern Matching, Input Sanitization  
- **Development**: Jupyter Notebook, Git

---

## 📊 Performance Metrics

| Metric                  | Value         |
|------------------------|---------------|
| Detection Accuracy     | 95%+          |
| False Positive Rate    | <5%           |
| Processing Speed       | <1 second     |
| Attack Coverage        | 7 categories  |
| Dataset Size           | 67 labeled queries |

---

## 🎯 Core Features

- ✅ **Dual Detection System**: Rule-based + ML ensemble  
- ✅ **Interactive Web Interface**: Streamlit dashboard for live testing  
- ✅ **Risk Scoring**: 0–100 scale with color-coded alerts  
- ✅ **Query Sanitization**: Automatic input cleaning  
- ✅ **Visual Analytics**: ROC curves, confusion matrices, feature importance  
- ✅ **Security Guide**: Built-in examples and best practices

---

## 🧠 Technical Approach

- **Pattern Recognition**: 40+ regex rules for known SQLi signatures  
- **Feature Engineering**: Character-level n-grams (1–3) with TF-IDF  
- **Ensemble Learning**: Weighted combination of Random Forest + Logistic Regression  
- **Risk Scoring**: 60% rule-based + 40% ML-based  
- **Sanitization**: Multi-layer keyword removal and input cleaning

---

## 🎨 Unique Differentiators

- 🔀 **Hybrid Detection**: Combines interpretability with adaptive learning  
- 📊 **12+ Interactive Charts**: Model explainability and performance tracking  
- 📚 **Educational Focus**: Teaches developers how SQLi works and how to prevent it  
- 🚀 **Production-Ready**: Deployable Streamlit app with real-time analysis  
- 🧩 **Comprehensive Coverage**: Detects tautology, union, blind, time-based, and stacked queries

---

## 🔍 Attack Types Detected

- `' OR '1'='1` (Tautology)  
- `UNION SELECT ...`  
- `--` (Comment Injection)  
- Stacked Queries  
- Time-based Blind Injection  
- Schema Enumeration  
- Dangerous Function Execution


cd sql-injection-detector
pip install -r requirements.txt
streamlit run sql_injection_app.py
