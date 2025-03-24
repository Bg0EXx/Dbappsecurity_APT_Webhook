# ✨️ 概述
 针对安恒明御 APT 攻击预警平台
 态势感知告警自定义企业微信 Webhook 外发脚本
 引入唯一的外部库是 [Drissionpage](https://www.drissionpage.cn/)
 兼顾浏览器自动化的便利性和 Requests 的高效率

---

# 💡 运行环境
 - Python 版本要求： 3.6 及以上
 - 操作系统：Windows、Linux 和 Mac
 - 支持浏览器：Chromium 内核（如 Chrome 和 Edge）

---

# 🛠 安装
  `pip install DrissionPage==4.1.0.17`
  或者
  `pip install -r requirements.txt`

---

# 📖 配置
 修改 config.ini
 - port 是浏览器调试控制端口
 - url 是安恒明御 APT 攻击预警平台地址
 - webhook_url 是企业微信 Webhook 机器人接口地址
 - accesssubtype 和 flags 是对应接口过滤条件字段
 - start_time 和 end_time 是查询起始结束时间
 - sleep_time 是轮询间隔休眠时间

---

# ☀️ 运行
 `python apt.py`
