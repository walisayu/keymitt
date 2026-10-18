# keymitt

**讓 AI 代理用得到你的密碼，卻永遠看不到。**

[English](README.md)

keymitt 是一個 [MCP](https://modelcontextprotocol.io) 伺服器加命令列工具。它把 API token、密碼與金鑰
放在作業系統的鑰匙圈裡，讓 AI 程式代理**使用**它們——但密碼值永遠不會進入代理的上下文、對話紀錄或日誌。

```text
代理：run_with_secrets { command: ["curl", "--config", "-"],
                        stdin: "header = \"Authorization: Bearer {{secret:github}}\"" }
          │
          ▼
keymitt ── 檢查政策 ── 你核准（Touch ID / Windows Hello / polkit）── 從鑰匙圈取值
          │
          ▼
curl 從 stdin 拿到真正的 token  ──►  回傳給代理的是  "token": "[REDACTED:github]"
```

像拿鑰匙用的隔熱手套：代理拿得起來，但手永遠碰不到。

> **狀態：早期版本（0.1）。** 設計是刻意的，但程式碼尚未經過稽核。
> keymitt 能防什麼、不能防什麼，請看 [SECURITY.md](SECURITY.md)（英文）。

## 為什麼需要它

代理一直撞到同一面牆：任務需要一組憑證。現在你只能把它貼進對話（從此永遠留在紀錄裡）、放進代理讀得到的檔案，
或乾脆自己動手。keymitt 提供第四條路：

- **密碼值留在作業系統的鑰匙圈**——macOS 鑰匙圈、Windows 認證管理員，或 Linux 的 Secret Service（GNOME Keyring、KWallet）。
- **代理只用名稱指稱密碼**，寫成 `{{secret:NAME}}` 佔位符。keymitt 在最後一刻才把值代入 stdin、環境變數、
  僅限擁有者讀寫的暫存檔或 HTTP 標頭——**絕不放進命令列參數**，因為其他程序讀得到參數。
- **每一次使用都由你在自己的裝置上核准**，而且是代理按不到的驗證視窗：macOS 用 Touch ID 或登入密碼、
  Windows 用 Windows Hello、Linux 用 polkit。
- **每組密碼都有政策**，規定哪些程式可以收到它、可以送往哪些主機。
- **代理拿回的一切都經過遮蔽**——不只用到的那組，而是**所有**密碼的值，連同它們的 base64、hex、URL 編碼與 JSON 跳脫形式。
- **稽核紀錄**記下每一次使用（絕不記錄值）。
- **加密、可攜的備份**（age 加通關密語），在任何平台都能還原。

## 平台支援

|            | macOS               | Windows                  | Linux                          |
|------------|---------------------|--------------------------|--------------------------------|
| 密碼存放   | 鑰匙圈              | 認證管理員               | Secret Service（D-Bus）        |
| 強驗證核准 | Touch ID／登入密碼  | Windows Hello（PIN、生物辨識） | polkit（`keymitt setup polkit`） |
| 弱驗證退路\* | CLI               | 是／否訊息框、CLI        | zenity／kdialog 詢問、CLI       |

\* 弱驗證只確認意圖、不驗證身分。只有在沒有強驗證可用，**而且** `allow_weak = true`（預設）時才會使用。
備份一律要求強驗證。

需求：`http_request` 需要 `PATH` 裡有 `curl`（macOS、Windows 10 以上與多數 Linux 發行版都內建）。
Windows 認證管理員每組密碼上限 2560 位元組。

## 安裝

一行就能裝好——它會下載你平台的版本、驗證 SHA-256 校驗碼，再把 `keymitt` 安裝到 `~/.local/bin`（預設）。

macOS 與 Linux：

```sh
curl -fsSL https://keymitt.walisayu.com/install.sh | sh
```

Windows（PowerShell）：

```powershell
irm https://keymitt.walisayu.com/install.ps1 | iex
```

或用 Rust 1.85 以上從原始碼建置：

```sh
git clone <這個 repository> keymitt
cd keymitt
cargo install --path .
```

檢查安裝（會在鑰匙圈寫入並刪除一筆探測項目）。加上 `--approval` 會另外跳出一次測試用的核准視窗：

```sh
keymitt doctor --approval
```

## 快速開始

**1. 存入一組密碼**——由你輸入值，不會回顯、也不會寫進磁碟。

```sh
keymitt add github --description "GitHub fine-grained token" --host api.github.com
keymitt add pg-staging --description "staging DB password" --command psql
```

如果 token 是從網頁複製的，加上 `--from-clipboard` 就會改從剪貼簿讀取（見[從剪貼簿存入密碼](#從剪貼簿存入密碼)）。
`--host` 允許 `http_request` 把密碼送到該主機；`--command` 允許某支程式透過 stdin、環境變數或暫存檔收到它——
像 `psql` 這樣只寫名稱時，會當場解析並存成完整路徑，讓政策只指向那一支程式。所有參數都可以重複指定，
之後用 `keymitt allow --help` 調整。

**2. 註冊 MCP 伺服器**到你的 AI 用戶端。以 Claude Code 為例，這會印出符合你安裝位置的 `claude mcp add …` 指令：

```sh
keymitt setup claude
```

任何能啟動 stdio 伺服器的 MCP 用戶端都能用，指令是 `keymitt mcp`。

**3. 請代理做事。**它會用 `list_secrets` 找到密碼，然後這樣使用：

```json
{ "tool": "http_request",
  "arguments": { "url": "https://api.github.com/user",
                 "headers": { "Authorization": "Bearer {{secret:github}}" } } }
```

```json
{ "tool": "run_with_secrets",
  "arguments": { "command": ["psql", "-h", "staging-db", "-U", "app", "-c", "select count(*) from users"],
                 "env": { "PGPASSWORD": "{{secret:pg-staging}}" } } }
```

畫面會跳出 Touch ID／Windows Hello／polkit 視窗，寫明到底要執行什麼。核准之後，代理收到的輸出裡
每一個密碼值都會變成 `[REDACTED:NAME]`。

## 從剪貼簿存入密碼

大部分 token 都是從網頁複製來的。與其貼進輸入提示，不如讓 keymitt 直接讀剪貼簿：

```sh
keymitt add github --description "GitHub fine-grained token" --host api.github.com --from-clipboard
keymitt update github --from-clipboard
```

```text
Read 93 characters from the clipboard.
Stored github in the macOS Keychain.
Cleared the clipboard.
```

- 頭尾的空白（例如結尾的換行）會自動去掉。keymitt 只顯示讀到幾個字元，絕不顯示內容。
- 存好之後，keymitt 會清空剪貼簿，但只在剪貼簿裡還是同一個值時才清：這段時間你另外複製的東西不會被動到。
  加上 `--keep-clipboard` 就保留剪貼簿不動。
- 剪貼簿是空的會直接報錯，絕不會存成空密碼。
- 剪貼簿歷程會自己留一份：Windows 的剪貼簿歷程（Win+V），以及 Maccy、Klipper 這類剪貼簿管理工具。
  記得也在那裡刪掉，或在複製時先暫停歷程。
- Linux 需要桌面環境（X11 或 Wayland）。在伺服器上請改用 `--from-stdin`，用管線把值傳進來。
- 只有 `keymitt` 命令列會讀剪貼簿。MCP 伺服器完全碰不到剪貼簿，因為剪貼簿裡常常就是你剛複製的密碼。

## 實際範例

日常工作只要設定一次：從服務商的網頁複製 token，用 `--from-clipboard` 存起來。

| 跟代理說 | 一次性設定 | 代理使用 |
| --- | --- | --- |
| 「列出 my-org/my-app 還沒關的 bug，從最舊的開始」 | `keymitt add github --host api.github.com --from-clipboard` | `http_request` 連到 `api.github.com` |
| 「建置文件，部署到 Cloudflare Pages」 | `keymitt add cloudflare --command wrangler --env CLOUDFLARE_API_TOKEN --from-clipboard` | `run_with_secrets` 執行 `wrangler pages deploy` |
| 「staging 這週有多少人註冊？」 | `keymitt add pg-staging --command psql --env PGPASSWORD --from-clipboard` | `run_with_secrets` 執行 `psql -c …` |
| 「把 release notes 貼到 Slack 的 #releases」 | 代理用 `request_secret` 請你存；你執行 `keymitt add slack-bot --host slack.com --from-clipboard` | `http_request` 連到 `slack.com` |

新增密碼之後，請在 AI 用戶端重新啟動 keymitt 伺服器（Claude Code：`/mcp` → keymitt → Reconnect）。
每次使用仍然需要你核准，核准視窗會顯示完整的指令或請求。
[實際範例頁面](https://keymitt.walisayu.com/zh/guide/examples)逐一說明每個範例的請求內容與核准畫面。

## 提供給代理的工具

| 工具                 | 作用 |
|----------------------|------|
| `list_secrets`       | 列出密碼的名稱、說明與允許的用途，絕不包含值。 |
| `run_with_secrets`   | 執行程式（不經 shell），密碼放進 `stdin`、`env` 的值，或以 `{{file:ID}}` 參照的暫存 `files`。 |
| `http_request`       | 由 keymitt 自己（透過 `curl`）送出請求，只送往允許的主機，不跟隨重新導向。 |
| `read_file_redacted` | 讀取設定檔，把所有已知密碼值**以及**看起來像憑證的值（密碼、token、私鑰、URL 裡的密碼）遮蔽掉。只能讀伺服器工作目錄與設定的目錄底下；憑證存放處與金鑰檔一律拒絕。 |
| `request_secret`     | 回傳一行 `keymitt add …` 指令讓**你**自己執行。代理被告知絕不能在對話中索取密碼值。 |

刻意不提供任何會回傳密碼值、匯出密碼或修改政策的工具。

## 政策檔

`~/.config/keymitt/policy.toml`（Windows 是 `%APPDATA%\keymitt\policy.toml`；可用 `KEYMITT_HOME` 覆寫）。
裡面沒有任何密碼值，可以放進你的 dotfiles。

```toml
version = 1

[approval]
method = "auto"        # auto | native（只用強驗證）| cli
ttl_secs = 0           # 對「完全相同」的請求記住核准幾秒；0 = 每次都問
timeout_secs = 120     # 沒人回應就拒絕
allow_weak = true      # 沒有強驗證可用時，允許弱驗證

[secrets.github]
description = "GitHub fine-grained token"
channels = ["http"]                   # stdin | env | file | http
hosts = ["api.github.com"]            # 也可以是 "*.example.com"、"http://127.0.0.1:8080"、"*"

[secrets.pg-staging]
description = "staging DB password"
channels = ["env", "stdin"]
commands = ["/opt/homebrew/bin/psql"]   # 完整路徑（`keymitt add --command psql` 會自動解析），或 "*"
env = ["PGPASSWORD"]                    # 選填：只能放進這些環境變數

[files]
read_roots = ["~/projects/infra"]       # read_file_redacted 額外可讀的目錄
```

只寫主機名稱時，只比對 HTTPS 的 443 埠。本機的明文 HTTP 服務請寫完整來源，例如 `http://127.0.0.1:3000`。
MCP 伺服器在啟動時讀取政策，修改後要重新啟動。

## 核准

每個請求都會跳出視窗，列出用到的密碼、完整的命令列（或方法與網址）以及工作目錄。如果你在驗證視窗按了取消，
請求就被拒絕——keymitt 在你說不之後，**絕不會**改用較弱的方式再問一次。只有在強驗證**無法使用**時才會退回
（例如透過 SSH 沒有 Touch ID／密碼介面、Windows Hello 沒設定、polkit 動作沒安裝）。

在沒有畫面的機器上，設定 `method = "cli"`，再從另一個終端機核准：

```sh
keymitt pending
keymitt approve 3f9c2a1b
```

## 備份與還原

備份——需要強驗證核准，以及一組至少 12 個字元的通關密語：

```sh
keymitt backup keymitt-2026-10.age
```

在任何作業系統還原——已有的值會保留，除非加上 `--overwrite`：

```sh
keymitt restore keymitt-2026-10.age
```

備份檔是 ASCII 封裝的 [age](https://age-encryption.org) 檔，用你的通關密語（scrypt）加密，內含政策與
每一組密碼的值——請把它當成密碼管理器的匯出檔來保管。備份與還原只能從命令列執行，永遠不開放給代理。

## 強化你的 AI 用戶端

keymitt 只保護**經過它**的密碼。有 shell 的代理仍然可以直接讀憑證檔。請在用戶端擋掉，讓代理改用
`read_file_redacted`。以 Claude Code 為例，在 `~/.claude/settings.json` 加上類似的規則（路徑請依你的環境調整）：

```json
{
  "permissions": {
    "deny": [
      "Read(**/.env)", "Read(**/.env.*)", "Read(**/*.pem)", "Read(**/*.key)",
      "Read(~/.pgpass)", "Read(~/.netrc)", "Read(~/.ssh/**)", "Read(~/.aws/credentials)"
    ]
  }
}
```

`cat .env` 這類 shell 指令沒辦法用樣式可靠地擋住，那裡要靠用戶端本身的權限確認把關。

## 一段話說完安全模型

keymitt 防的是**意外**外洩——密碼被印進對話紀錄、寫進日誌、或被貼進聊天——並讓每一次**使用**都被看見、
經過人核准。它不是用來對付「刻意作惡、能以你的身分任意執行指令」的代理的沙箱：這樣的代理可以直接讀
Linux 的 Secret Service。完整的威脅模型請看 [SECURITY.md](SECURITY.md)。

## 開發

單元測試與端對端 MCP 測試，再跑 lint：

```sh
cargo test --features testing
cargo clippy --all-targets --features testing
```

`testing` feature 會編入記憶體保險箱與腳本化核准，只供測試使用。**絕不要**安裝或散布開啟這個 feature 的版本。

## 參與貢獻

這個 repository 會在每次發佈時更新成一份快照，所以歷史只有一個 commit。歡迎開 issue 或 pull request：
接受的修改會在上游套用，並出現在下一次發佈的快照裡。

## 授權

依你的選擇，採用 [Apache License 2.0](LICENSE-APACHE) 或 [MIT 授權](LICENSE-MIT)。除非你另外明確聲明，
任何有意提交並納入 keymitt 的貢獻，都依上述方式雙重授權，不附加其他條款或條件。
