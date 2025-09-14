
<div align="center">
  <h2 align="center">Discord Passwordless Token Changer</h2>
  <p align="center">
    An automated tool for updating Discord tokens using passwordless remote authentication, with proxy support, multi-threading, and real-time progress tracking.
    <br />
    <br />
    <a href="https://discord.cyberious.xyz">💬 Discord</a>
    ·
    <a href="#-changelog">📜 ChangeLog</a>
    ·
    <a href="https://github.com/sexfrance/Discord-Passwordless-Token-Changer/issues">⚠️ Report Bug</a>
    ·
    <a href="https://github.com/sexfrance/Discord-Passwordless-Token-Changer/issues">💡 Request Feature</a>
  </p>
</div>

---

### ⚙️ Installation

- Requires: `Python 3.7+`
- Create a python virtual environment: `python3 -m venv venv`
- Activate the environment: `venv\Scripts\activate` (Windows) / `source venv/bin/activate` (macOS, Linux)
- Install dependencies: `pip install -r requirements.txt`

---

### 🔥 Features

- Automated Discord token updating via passwordless remote authentication
- Proxy support for avoiding rate limits
- Multi-threaded token processing
- Real-time progress tracking in the console title
- Configurable thread count
- Debug mode for troubleshooting
- Proxy/Proxyless mode support
- Automatic removal of processed tokens from input
- Output folder opens automatically after processing

---

### 📝 Usage

1. **Configuration**:
   Edit `input/config.toml`:

   ```toml
   [dev]
   Debug = false
   Proxyless = false
   Threads = 1
   ```

2. **Proxy Setup** (Optional):

   - Add proxies to `input/proxies.txt` (one per line)
   - Format: `ip:port` or `user:pass@ip:port`

3. **Token Input**:

   - Add tokens to `input/tokens.txt` (one per line)
   - Format: `token` or `email:pass:token`

4. **Running the script**:

   ```powershell
   python main.py
   ```

5. **Output**:
   - Updated tokens are saved to `output/<timestamp>/tokens.txt`
   - Invalid tokens to `output/<timestamp>/invalid.txt`
   - Failed attempts to `output/<timestamp>/failed.txt`
   - The output folder will open automatically after processing

---

### 📹 Preview

![Preview](https://i.imgur.com/un2ZOiM.gif)

---

### ❗ Disclaimers

- This project is for educational purposes only
- The author is not responsible for any misuse of this tool
- Use responsibly and in accordance with Discord's terms of service

---

### 📜 ChangeLog

```diff
v0.0.1 ⋮ 09/14/2025
! Initial release.
```

<p align="center">
  <img src="https://img.shields.io/github/license/sexfrance/Discord-Passwordless-Token-Changer.svg?style=for-the-badge&labelColor=black&color=f429ff&logo=IOTA"/>
  <img src="https://img.shields.io/github/stars/sexfrance/Discord-Passwordless-Token-Changer.svg?style=for-the-badge&labelColor=black&color=f429ff&logo=IOTA"/>
  <img src="https://img.shields.io/github/languages/top/sexfrance/Discord-Passwordless-Token-Changer.svg?style=for-the-badge&labelColor=black&color=f429ff&logo=python"/>
</p>
