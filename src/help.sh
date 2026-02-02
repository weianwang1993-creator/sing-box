show_help() {
    case $1 in
    api | x25519 | tls | run | uuid | version)
        $is_core_bin help $1 ${@:2}
        ;;
    *)
        [[ $1 ]] && warn "未知選項 '$1'"
        msg
        _box_top 50
        _box_line 50 "$is_core_name script $is_sh_ver by $author"
        _box_bot 50
        msg "Usage: $is_core [options]... [args]... "
        msg
        help_info=(
            "基本:"
            "   v, version                                      顯示目前版本"
            "   ip                                              傳回目前主機的 IP"
            "   pbk                                             等同於 $is_core generate reality-keypair"
            "   get-port                                        傳回一個可用的連接埠"
            "   ss2022                                          傳回一個可用於 Shadowsocks 2022 的密碼\n"
            "一般:"
            "   a, add [protocol] [args... | auto]              新增設定"
            "   c, change [name] [option] [args... | auto]      變更設定"
            "   d, del [name]                                   刪除設定**"
            "   i, info [name]                                  檢視設定"
            "   qr [name]                                       二維碼資訊"
            "   url [name]                                      URL 資訊"
            "   log                                             檢視日誌"
            "變更:"
            "   full [name] [...]                               變更多個參數"
            "   id [name] [uuid | auto]                         變更 UUID"
            "   host [name] [domain]                            變更網域"
            "   port [name] [port | auto]                       變更連接埠"
            "   path [name] [path | auto]                       變更路徑"
            "   passwd [name] [password | auto]                 變更密碼"
            "   key [name] [Private key | atuo] [Public key]    變更密鑰"
            "   method [name] [method | auto]                   變更加密方式"
            "   sni [name] [ ip | domain]                       變更 serverName"
            "   new [name] [...]                                變更協定"
            "   web [name] [domain]                             變更偽裝網站\n"
            "進階:"
            "   dns [...]                                       設定 DNS"
            "   dd, ddel [name...]                              刪除多個設定**"
            "   fix [name]                                      修復一個設定"
            "   fix-all                                         修復全部設定"
            "   fix-caddyfile                                   修復 Caddyfile"
            "   fix-config.json                                 修復 config.json"
            "   import                                          匯入 xray/v2ray 腳本設定\n"
            "管理:"
            "   un, uninstall                                   解除安裝"
            "   u, update [core | sh | caddy] [ver]             更新"
            "   U, update.sh                                    更新腳本"
            "   s, status                                       執行狀態"
            "   start, stop, restart [caddy]                    啟動, 停止, 重新啟動"
            "   t, test                                         測試運行"
            "   reinstall                                       重新安裝腳本\n"
            "測試:"
            "   debug [name]                                    顯示一些 debug 資訊, 僅供參考"
            "   gen [...]                                       等同於 add, 但只顯示 JSON 內容, 不建立檔案, 測試使用"
            "   no-auto-tls [...]                               等同於 add, 但禁止自動設定 TLS, 可用於 *TLS 相關協定"
            "其他:"
            "   bbr                                             啟用 BBR, 如果支援"
            "   bin [...]                                       執行 $is_core_name 指令, 例如: $is_core bin help"
            "   [...] [...]                                     相容絕大多數的 $is_core_name 指令, 例如: $is_core_name generate uuid"
            "   h, help                                         顯示此說明畫面\n"
        )
        for v in "${help_info[@]}"; do
            msg "$v"
        done
        msg "謹慎使用 del, ddel, 此選項會直接刪除設定; 無需確認"
        msg "回報問題) $(msg_ul https://github.com/${is_sh_repo}/issues) "
        msg "文件(doc) $(msg_ul https://233boy.com/$is_core/$is_core-script/)"
        ;;

    esac
}

about() {
    msg
    _box_top 50
    _box_line 50 "關於 $is_core_name script"
    _box_bot 50
    msg
    msg "Github: $(msg_ul https://github.com/${is_sh_repo})"
    msg "$is_core_name 官網: $(msg_ul https://sing-box.sagernet.org/)"
    msg "$is_core_name 核心: $(msg_ul https://github.com/${is_core_repo})"
    msg
}
