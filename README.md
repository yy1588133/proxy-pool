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

- **🚀 节点选择**：总开关，可在下列各组之间切换，也可 DIRECT 直连或手动指定单个节点
- **⚡ 自动最快**：包含**全部节点**的 url-test 组，每 5 分钟以 `youtube.com/generate_204` 测速并自动切换最快节点（大池子不宜高频测速）
- **国家/地区组**：每个国家一个 url-test 组（如 `🇯🇵 日本·141`），只在该国节点内自动选最快；测速间隔差异化——节点 ≥100 的组每 2 分钟，<100 的组每 1 分钟；节点少于 3 个的国家归入 `🌍 其他`，无法识别归属的归入 `🏳️ 未标注`
- 国别识别：优先解析节点名（国旗 emoji / 中文国名 / ISO 代码），识别失败的再用 GeoIP 按服务器 IP 归属地补识别

分流规则：内网 IP 直连 → GEOIP CN 直连 → 其余走代理。

## 使用建议

1. 客户端把订阅**自动更新间隔设为 6 小时**（与仓库更新节奏一致）
2. 平时挂在 **⚡ 自动最快** 组即可，死节点会被自动跳过
3. 免费节点波动大，看视频卡顿就手动换一个低延迟节点

## 上游源

[freeSub](https://github.com/Ruk1ng001/freeSub) · [NoMoreWalls](https://github.com/peasoft/NoMoreWalls) · [AutoMergePublicNodes](https://github.com/chengaopan/AutoMergePublicNodes) · [zhuhaiuk/free-nodes](https://github.com/zhuhaiuk/free-nodes) · [free18](https://github.com/free18/v2ray) · [get_subscribe](https://github.com/ermaozi/get_subscribe) · [clashfree](https://github.com/free-nodes/clashfree) · [V2RayAggregator](https://github.com/mahdibland/V2RayAggregator) · [Free-servers](https://github.com/Pawdroid/Free-servers)

> 候选源均经过墙内真实环境抽样测活筛选；Epodonios、MhdiTaheri、Alirewa、miladtahanian 等 Telegram 收集器因服务器大面积被墙未收录

## 当前统计

<!--STATS-->
更新于 **2026-09-01 13:18:18 北京时间**，共 **2296** 个去重节点

| 上游源 | 节点数 |
|---|---|
| freeSub | 433 |
| NoMoreWalls | 292 |
| AutoMerge | 0 |
| zhuhaiuk | 17 |
| free18 | 158 |
| ermaozi | 12 |
| clashfree | 1224 |
| Eternity | 155 |
| Pawdroid | 5 |
<!--/STATS-->

## 声明

节点均来自互联网公开资源，仅供学习交流，请遵守当地法律法规。
