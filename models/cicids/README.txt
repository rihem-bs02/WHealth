Optional CICIDS2017 Network AI model folder
================================================

The default Network Audit tab is rule-based and fast. It does not need any files here.

To enable the optional CICIDS-style AI engine, add:

1. cicids_model.joblib
   A trained model that supports predict() and optionally predict_proba().

2. feature_columns.json or feature_columns.txt
   The exact feature column order expected by your trained model.

Important:
Most CICIDS2017 models expect packet/flow features such as Flow Duration,
Total Fwd Packets, Flow Bytes/s, SYN Flag Count, etc. The fast endpoint
network audit only sees active connections from psutil and cannot produce
those fields. Use CICFlowMeter, Zeek, Suricata, or a custom flow extractor to
produce a compatible flow CSV before enabling this AI model.

The app will never sniff traffic or upload network data by default.
