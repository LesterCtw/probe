# probe

`probe.py` 是一個只使用 Python standard library 的環境檢查工具，主要用來檢查受限制的 Windows / Python 環境，例如公司電腦不能安裝套件、不能把完整檔案帶出來、或需要用數字摘要回家後再解讀的情境。

它預設會：

- 不安裝任何東西。
- 不連網，除非你加上 `--network`。
- 不執行外部工具指令，除非你加上 `--run-tool-commands` 或 `--run-pip-commands`。
- 產生一組可手抄的 numeric summary code。
- 在允許寫檔時輸出 JSON 與 Markdown 報告。
- 在文字報告中遮蔽常見 secret、使用者名稱、電腦名稱與路徑資訊。

## 需求

- Python 3.10 以上。
- 建議使用 Python 3.12，因為這個工具是針對 Windows 11 / Python 3.12 環境設計。
- 不需要安裝第三方套件。

## 快速使用

下載或複製 `probe.py` 到要檢查的機器上，然後執行：

```bash
python probe.py
```

執行完成後，終端機會顯示一組 numeric summary code，並在目前目錄建立 `probe_results/` 資料夾，裡面包含：

- `probe_YYYYMMDD_HHMMSS.json`：完整結構化報告。
- `probe_YYYYMMDD_HHMMSS.md`：可讀性較高的 Markdown 報告。
- `probe_latest.json`：最新一次 JSON 報告。
- `probe_latest.md`：最新一次 Markdown 報告。

如果公司規定不能帶出檔案，請只抄終端機印出的 numeric summary code。

## 常用指令

基本檢查，不連網、不跑外部工具指令：

```bash
python probe.py
```

只輸出 numeric summary code，不印其他說明：

```bash
python probe.py --numeric-only
```

不寫入 JSON / Markdown 檔案，只在終端機顯示結果：

```bash
python probe.py --no-files
```

指定輸出資料夾：

```bash
python probe.py --output-dir my_probe_results
```

測試 PyPI、Python.org、GitHub 的 DNS、TLS 與 HTTPS 可達性：

```bash
python probe.py --network
```

掃描 PATH 上有哪些工具，並額外執行工具版本指令，例如 `git --version`、`java -version`：

```bash
python probe.py --run-tool-commands
```

執行較慢但更完整的 pip 檢查，例如 `pip debug`、`pip list`、`pip config`、`pip freeze`：

```bash
python probe.py --run-pip-commands
```

把 timeout 調長到 15 秒，適合公司網路或 pip 指令很慢的環境：

```bash
python probe.py --network --run-pip-commands --timeout 15
```

## 回家後解讀 numeric summary code

如果你只能從公司電腦帶回一串數字，可以在另一台有 `probe.py` 的電腦上解讀：

```bash
python probe.py --decode 312801...
```

也可以貼上含空格或 dash 的格式，程式會自動只取數字：

```bash
python probe.py --decode "3128 01..."
```

解讀結果會列出每個欄位代表的檢查項目，例如 Python 版本、pip 是否可 import、是否能寫入目錄、是否偵測到 proxy、PyPI / GitHub 網路測試是否成功等。

## 典型工作流程

在公司 Windows 機器上先跑最保守版本：

```bash
python probe.py --no-files
```

如果允許寫本機檔案，可以改跑：

```bash
python probe.py
```

如果需要確認 PyPI / GitHub 是否被公司網路擋住，再跑：

```bash
python probe.py --network
```

如果要診斷 pip 設定或套件狀態，再跑較完整版本：

```bash
python probe.py --network --run-pip-commands --timeout 15
```

最後把 numeric summary code 或允許帶出的報告帶回家分析。

## 安全注意事項

預設輸出的 JSON / Markdown 會遮蔽常見敏感資訊，例如 token、password、credential、cookie、cert、key、使用者名稱、電腦名稱與家目錄路徑。

如果你確定公司政策允許輸出完整資訊，才使用：

```bash
python probe.py --unsafe-full
```

`--unsafe-full` 會關閉遮蔽，可能輸出敏感資訊。一般情況不建議使用。

## 參數總覽

| 參數 | 用途 |
|---|---|
| `--output-dir DIR` | 指定 JSON / Markdown 報告輸出資料夾，預設是 `probe_results`。 |
| `--timeout SECONDS` | 指定每個外部指令或網路測試的 timeout 秒數，預設是 `8`。 |
| `--network` | 執行 DNS、TLS、HTTPS 網路測試。 |
| `--no-files` | 不寫入報告檔案，只印終端機輸出。 |
| `--numeric-only` | 只印 numeric summary code。 |
| `--decode CODE` | 解讀 numeric summary code 後結束。 |
| `--unsafe-full` | 關閉遮蔽，輸出完整資訊。請只在政策允許時使用。 |
| `--run-tool-commands` | 執行外部工具版本指令。 |
| `--run-pip-commands` | 執行 pip 相關診斷指令。 |

## 疑難排解

如果 `python probe.py` 顯示找不到 Python，請在 Windows 上試：

```powershell
py probe.py
```

如果網路檢查很慢或 timeout，請增加 timeout：

```bash
python probe.py --network --timeout 15
```

如果無法寫入報告檔案，請改用：

```bash
python probe.py --no-files
```

如果終端機中文或特殊字元顯示異常，numeric summary code 仍然可以使用，因為它只包含數字。
