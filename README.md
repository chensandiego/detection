使用 Scapy 進行封包攔截與處理

使用 機器學習模型（例如 isolation forest）做異常偵測

使用 簽章比對 來偵測已知威脅

支援 即時處理與警示

安裝所需套件
pip install scapy scikit-learn joblib

 模型訓練範例（一次性操作）
你可以先蒐集正常網路行為的特徵資料並訓練模型：

from sklearn.ensemble import IsolationForest
from joblib import dump

# 假設這些是來自正常網路的封包特徵
X_train = [
    [60, 64, 6, 60],
    [70, 64, 17, 64],
    [54, 64, 6, 54],
]

model = IsolationForest(contamination=0.1)
model.fit(X_train)
dump(model, 'model/isolation_forest_model.joblib')
