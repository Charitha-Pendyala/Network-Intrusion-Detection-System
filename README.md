# 🛡️ Network Intrusion Detection System (NIDS)

An **AI-powered Network Intrusion Detection System** that analyzes network traffic records and detects malicious activity using machine learning.  
The project includes **model training**, **feature-consistent inference**, and a **cloud-deployed Streamlit dashboard** for interactive analysis.

---

## 🚀 Live Application

🔗 **Streamlit Demo:**  
https://network-intrusion-detection-system-qxaj8svokjhedpe6opzrjh.streamlit.app/

Upload an **NSL-KDD–formatted CSV file** to analyze network traffic and generate severity-based intrusion alerts.

---

## 📌 Project Overview

This project demonstrates an **end-to-end machine learning workflow** for intrusion detection:

- Data preprocessing and feature engineering  
- Supervised and unsupervised learning  
- Model persistence and reuse  
- Frontend dashboard for real-time–style analysis  
- Cloud deployment using **GitHub + Streamlit Cloud**

The system classifies traffic as **normal or attack** and assigns a **severity level** based on model outputs.

---

## 🧠 Machine Learning Approach

### Models Used

**Random Forest Classifier**  
- Detects known intrusion patterns using supervised learning.

**Isolation Forest**  
- Detects anomalous traffic behavior using unsupervised learning.

### Alert Severity Logic

| Severity  | Meaning |
|----------|--------|
| SAFE     | Normal traffic |
| MEDIUM   | Anomalous behavior detected |
| HIGH     | Known attack pattern detected |
| CRITICAL | Both models agree on intrusion |

---

## 📂 Dataset

- **NSL-KDD Dataset**
- Widely used benchmark dataset for intrusion detection research
- Includes **41 traffic features** and labeled attack types

**Note:**  
The raw dataset is not included due to size.  
A sample CSV file is provided for testing the application.

---

## 🗂️ Project Structure

Network-Intrusion-Detection-System/
├── app.py # Streamlit dashboard
├── NIDS_training_notebook.ipynb # Model training (Google Colab)
├── rf_model.pkl # Trained Random Forest model
├── iso_model.pkl # Trained Isolation Forest model
├── scaler.pkl # Feature scaler
├── feature_columns.pkl # Saved feature schema
├── nsl_kdd_upload.csv # Sample input CSV
├── requirements.txt # Dependencies
└── README.md


---

## ⚙️ How the System Works

### Training Phase
- Performed in **Google Colab** (`NIDS_training_notebook.ipynb`)
- Categorical features are **one-hot encoded**
- Feature schema is saved to prevent mismatch during inference
- Models and scaler are exported as `.pkl` files

### Inference Phase
- User uploads a CSV file via Streamlit
- Same preprocessing pipeline is applied
- Features are aligned using the saved schema
- Predictions and alert severity are generated

### Visualization
- Metrics dashboard
- Bar and pie charts for alert distribution
- Filterable alert table
- Downloadable CSV report

---

## 🖥️ Run Locally

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Charitha-Pendyala/Network-Intrusion-Detection-System.git
cd Network-Intrusion-Detection-System
