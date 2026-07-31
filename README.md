# proxy-pool

自动聚合多个公开免费节点源，去重后生成 **Clash** 和 **v2rayN** 两种订阅，每 6 小时由 GitHub Actions 自动更新。

## 订阅地址

| 客户端 | 订阅链接（墙内优先用镜像） |
|---|---|
| **Clash / Mihomo / FlClash / Clash Verge** | `https://gh-proxy.com/raw.githubusercontent.com/yy1588133/proxy-pool/main/clash.yaml` |
| **v2rayN / v2rayNG / Shadowrocket** | `https://gh-proxy.com/raw.githubusercontent.com/yy1588133/proxy-pool/main/v2ray.txt` |

原始地址（海外或已有代理时可用）：

```
https://raw.githubusercontent.com/yy1588133/proxy-pool/main/clash.yaml
https://raw.githubusercontent.com/yy1588133/proxy-pool/main/v2ray.txt
```

## Clash 版内置策略组

- **🚀 节点选择**：手动选节点（或选 DIRECT 直连）
- **⚡ 自动最快**：url-test 组，每 5 分钟以 `youtube.com/generate_204` 测速，自动切换到最快节点

分流规则：内网 IP 直连 → GEOIP CN 直连 → 其余走代理。

## 使用建议

1. 客户端把订阅**自动更新间隔设为 6 小时**（与仓库更新节奏一致）
2. 平时挂在 **⚡ 自动最快** 组即可，死节点会被自动跳过
3. 免费节点波动大，看视频卡顿就手动换一个低延迟节点

## 上游源

[freeSub](https://github.com/Ruk1ng001/freeSub) · [clashfree](https://github.com/free-nodes/clashfree) · [V2RayAggregator](https://github.com/mahdibland/V2RayAggregator) · [Free-servers](https://github.com/Pawdroid/Free-servers)

## 当前统计

<!--STATS-->
更新于 **2026-07-31 13:54:07 北京时间**，共 **1180** 个去重节点

| 上游源 | 节点数 |
|---|---|
| freeSub | 216 |
| clashfree | 791 |
| Eternity | 159 |
| Pawdroid | 14 |
<!--/STATS-->

## 声明

节点均来自互联网公开资源，仅供学习交流，请遵守当地法律法规。
