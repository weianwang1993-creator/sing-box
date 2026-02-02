# 介紹

最好用的 sing-box 一鍵安裝腳本 & 管理腳本

基於 [233boy/sing-box](https://github.com/233boy/sing-box) 修改

# 特點

- 快速安裝
- 無敵好用
- 零學習成本
- 自動化 TLS
- 簡化所有流程
- 相容 sing-box 指令
- 強大的快捷參數
- 支援所有常用協定
- 一鍵新增 VLESS-REALITY (預設)
- 一鍵新增 TUIC
- 一鍵新增 Trojan
- 一鍵新增 Hysteria2
- 一鍵新增 Shadowsocks 2022
- 一鍵新增 VMess-(TCP/HTTP/QUIC)
- 一鍵新增 VMess-(WS/H2/HTTPUpgrade)-TLS
- 一鍵新增 VLESS-(WS/H2/HTTPUpgrade)-TLS
- 一鍵新增 Trojan-(WS/H2/HTTPUpgrade)-TLS
- 一鍵啟用 BBR
- 一鍵更改偽裝網站
- 一鍵更改 (連接埠/UUID/密碼/網域/路徑/加密方式/SNI/等...)
- 還有更多...

# 設計理念

設計理念為：**高效率，超快速，極易用**

腳本基於作者的自身使用需求，以 **多設定同時運行** 為核心設計

並且專門優化了，新增、更改、查看、刪除、這四項常用功能

你只需要一條指令即可完成 新增、更改、查看、刪除、等操作

例如，新增一個設定僅需不到 1 秒！瞬間完成新增！其他操作亦是如此！

腳本的參數非常高效率並且超級易用，請掌握參數的使用

# 文件

安裝及使用：https://github.com/weianwang1993-creator/sing-box

# 說明

使用：`sing-box help`

```
sing-box script v1.0 by weianwang1993
Usage: sing-box [options]... [args]...

基本:
   v, version                                      顯示目前版本
   ip                                              回傳目前主機的 IP
   pbk                                             同等於 sing-box generate reality-keypair
   get-port                                        回傳一個可用的連接埠
   ss2022                                          回傳一個可用於 Shadowsocks 2022 的密碼

一般:
   a, add [protocol] [args... | auto]              新增設定
   c, change [name] [option] [args... | auto]      更改設定
   d, del [name]                                   刪除設定**
   i, info [name]                                  查看設定
   qr [name]                                       二維碼資訊
   url [name]                                      URL 資訊
   log                                             查看日誌
更改:
   full [name] [...]                               更改多個參數
   id [name] [uuid | auto]                         更改 UUID
   host [name] [domain]                            更改網域
   port [name] [port | auto]                       更改連接埠
   path [name] [path | auto]                       更改路徑
   passwd [name] [password | auto]                 更改密碼
   key [name] [Private key | auto] [Public key]    更改金鑰
   method [name] [method | auto]                   更改加密方式
   sni [name] [ ip | domain]                       更改 serverName
   new [name] [...]                                更改協定
   web [name] [domain]                             更改偽裝網站

進階:
   dns [...]                                       設定 DNS
   dd, ddel [name...]                              刪除多個設定**
   fix [name]                                      修復一個設定
   fix-all                                         修復全部設定
   fix-caddyfile                                   修復 Caddyfile
   fix-config.json                                 修復 config.json
   import                                          匯入 sing-box/v2ray 腳本設定

管理:
   un, uninstall                                   解除安裝
   u, update [core | sh | caddy] [ver]             更新
   U, update.sh                                    更新腳本
   s, status                                       執行狀態
   start, stop, restart [caddy]                    啟動, 停止, 重新啟動
   t, test                                         測試執行
   reinstall                                       重裝腳本

測試:
   debug [name]                                    顯示一些 debug 資訊, 僅供參考
   gen [...]                                       同等於 add, 但只顯示 JSON 內容, 不建立檔案, 測試使用
   no-auto-tls [...]                               同等於 add, 但禁止自動設定 TLS, 可用於 *TLS 相關協定
其他:
   bbr                                             啟用 BBR, 如果支援
   bin [...]                                       執行 sing-box 指令, 例如: sing-box bin help
   [...] [...]                                     相容絕大多數的 sing-box 指令, 例如: sing-box generate uuid
   h, help                                         顯示此說明畫面

謹慎使用 del, ddel, 此選項會直接刪除設定; 無需確認
回報問題) https://github.com/weianwang1993-creator/sing-box/issues
文件(doc) https://github.com/weianwang1993-creator/sing-box
```
