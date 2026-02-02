is_log_level_list=(
    trace
    debug
    info
    warn
    error
    fatal
    panic
    none
    del
)
log_set() {
    if [[ $1 ]]; then
        for v in ${is_log_level_list[@]}; do
            [[ $(grep -E -i "^${1,,}$" <<<$v) ]] && is_log_level_use=$v && break
        done
        [[ ! $is_log_level_use ]] && {
            err "無法識別 log 參數: $@ \n請使用 $is_core log [${is_log_level_list[@]}] 進行相關設定.\n備註: del 參數僅臨時刪除 log 檔案; none 參數將不會產生 log 檔案."
        }
        case $is_log_level_use in
        del)
            rm -rf $is_log_dir/*.log
            msg "\n $(_green 已臨時刪除 log 檔案, 如果您想要完全禁止產生 log 檔案請使用: $is_core log none)\n"
            ;;
        none)
            rm -rf $is_log_dir/*.log
            cat <<<$(jq '.log={"disabled":true}' $is_config_json) >$is_config_json
            ;;
        *)
            cat <<<$(jq '.log={output:"/var/log/'$is_core'/access.log",level:"'$is_log_level_use'","timestamp":true}' $is_config_json) >$is_config_json
            ;;
        esac

        manage restart &
        [[ $1 != 'del' ]] && msg "\n已更新 Log 設定為: $(_green $is_log_level_use)\n"
    else
        if [[ -f $is_log_dir/access.log ]]; then
            msg "\n 提醒: 按 $(_green Ctrl + C) 退出\n"
            tail -f $is_log_dir/access.log
        else
            err "無法找到 log 檔案."
        fi
    fi
}
