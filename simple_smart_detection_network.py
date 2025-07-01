from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from joblib import load
import time
import json

# 已知攻擊簽章（可以來自 Threat Intelligence Feed）
KNOWN_SIGNATURES = [
    {"dst_port": 4444, "pattern": "shellcode"},
    {"src_ip": "192.168.1.100", "dst_port": 80},
]

# 匿名異常檢測模型 (先前訓練好的)
MODEL_PATH = "model/isolation_forest_model.joblib"

# 載入訓練好的模型
model = load(MODEL_PATH)

# 封包轉換為特徵
def extract_features(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        return [
            len(pkt),  # 封包大小
            ip_layer.ttl,
            ip_layer.proto,
            ip_layer.len,
        ]
    return [0, 0, 0, 0]

# 簽章比對
def match_signature(pkt):
    for sig in KNOWN_SIGNATURES:
        if "src_ip" in sig and pkt[IP].src != sig["src_ip"]:
            continue
        if "dst_port" in sig and TCP in pkt and pkt[TCP].dport != sig["dst_port"]:
            continue
        return True
    return False

# 警示輸出
def raise_alert(pkt, reason):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    alert = {
        "time": timestamp,
        "src": pkt[IP].src,
        "dst": pkt[IP].dst,
        "reason": reason
    }
    print("[ALERT]", json.dumps(alert, ensure_ascii=False))

# 主封包分析邏輯
def packet_handler(pkt):
    if IP not in pkt:
        return

    if match_signature(pkt):
        raise_alert(pkt, "Signature matched")

    features = extract_features(pkt)
    prediction = model.predict([features])
    if prediction[0] == -1:
        raise_alert(pkt, "Anomaly detected")

# 開始封包攔截
print("🚨 正在啟動智能混合型入侵偵測系統...")
sniff(prn=packet_handler, store=False)
