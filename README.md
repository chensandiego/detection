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

進階功能 1：整合 Suricata 規則（簽章）進行比對
 進階功能 2：離線分析 PCAP 檔案

                   +--------------------+
                   | Suricata Rules     |
                   | (signatures.rules) |
                   +--------+-----------+
                            |
                            v
+----------+       +-------------------+       +------------------+
|  PCAP    +------->  Packet Handler   +------->  Signature Match |
|  Replayer|       |  (real-time/pcap) |       +------------------+
+----------+       |                   |         +--------------------+
                   |                   +---------> Anomaly Detection  |
                   |                   |         +--------------------+
                   +-------------------+          
                            |
                            v
                    +------------------+
                    |   Alert Logger   |
                    +------------------+

smart_ids.zip（basic features)
once unzip
cd smart_ids

# 建立 image
docker build -t smart-ids .

# 即時封包偵測
docker run --net=host --cap-add=NET_ADMIN -it smart-ids

smart_ids_full.zip(include web interface)
unzip smart_ids_full.zip
cd smart_ids_full

# 建立 Docker Image
docker build -t smart-ids-full .

# 執行偵測與 Web Dashboard（LINE_TOKEN 與 SLACK_WEBHOOK 可選）
docker run --net=host --cap-add=NET_ADMIN -e LINE_TOKEN="你的LineToken" -e SLACK_WEBHOOK="你的SlackWebhook" -it smart-ids-full


新增
| 功能                            | 說明                           |
| ----------------------------- | ---------------------------- |
| ✅ 自動封鎖 IP                     | 當偵測到惡意行為時，自動封鎖來源 IP（例如加入防火牆） |
| ✅ 解封誤判 IP                     | 從網頁介面或 CLI 移除封鎖              |
| ✅ 永久/暫時封鎖                     | 可設定封鎖多久後自動解除（可選）             |
| ✅ Web Dashboard 顯示目前封鎖的 IP 清單 |                              |


CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    blocked_at TEXT,
    reason TEXT
);

smart_ids_block（加入自動封鎖,解封,永久/暫時封鎖

# 解壓縮
unzip smart_ids_block.zip
cd smart_ids_block

# 建立 Image
docker build -t smart-ids-block .

# 執行 IDS（自動封鎖 + 解封 + Web UI）
docker run --net=host --cap-add=NET_ADMIN -e LINE_TOKEN="你的LINE_TOKEN" -e SLACK_WEBHOOK="你的SlackWebhook" -it smart-ids-block

| 檔案                  | 說明                   |
| ------------------- | -------------------- |
| `firewall.py`       | 封鎖/解封 IP 邏輯，支援時間與白名單 |
| `unblock_daemon.py` | 守護進程，定時自動解封          |
| `whitelist.txt`     | 不應被封鎖的 IP 列表         |
| `dashboard.py`      | Web 介面，顯示封鎖清單並提供解封   |
| `blocked.html`      | Web 頁面樣板             |
| `docker_cmd.sh`     | 啟動 IDS + 解封服務的指令     |

