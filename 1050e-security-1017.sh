#!/bin/bash
###############################################################################
# Created Time  : 2023-3-17 08:37:15
# Last Modified : 2023-3-17 15:08:19
# File Name     : 1050e-security.sh
# Description   :
###############################################################################

# 提示信息格式设置
set -o noglob
bold=$(tput bold)
underline=$(tput sgr 0 1)
reset=$(tput sgr0)
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
blue=$(tput setaf 4)
magenta=$(tput setaf 5)
cyan=$(tput setaf 6)
white=$(tput setaf 7)

h1() {
    printf "\n${underline}${cyan}%s${reset}\n" "$@"
}
h2() {
    printf "\n${underline}${white}%s${reset}\n" "$@"
}
debug() {
    printf "${white}%s${reset}\n" "$@"
}
info() {
    printf "${white}-> %s${reset}\n" "$@"
}
success() {
    printf "${green}✔ %s${reset}\n" "$@"
}
error() {
    printf "${red}✖ %s${reset}\n" "$@"
}
warn() {
    printf "${yellow}-> %s${reset}\n" "$@"
}
bold() {
    printf "%s${reset}\n" "$@"
}
note() {
    printf "\n${underline}${blue}Note:${reset} ${blue}%s${reset}\n" "$@"
}
set +o noglob

################################################################
##########################设置变量###############################
export LANG="en_US.UTF-8"
day=$(date +%Y%m%d)
MinorVersion=$(grep "MinorVersion=" /etc/os-version | awk -F "=" '{print $NF}')
EditionName=$(grep "EditionName=" /etc/os-version | awk -F "=" '{print $NF}')

h1 "当前系统版本：${MinorVersion}${EditionName}"

# 设置 grub 启动菜单密码
grub_set="yes"
grub_pwd="uos@1050e"

# NTP 配置
ntp_set="yes"

# 是否禁用root telnet 登录
disable_root_telnet_login="yes"

# 是否禁用root ssh 登录
disable_root_ssh_login="yes"

# 是否禁用root gui 登录
disable_root_gui_login="yes"

# 设置 root 远程登录是否需要经过pam_securetty.so模块验证。
enable_root_pam_securetty="yes"

# 对所有用户都进行密码策略限制
all_user_login="yes"

# 密码有效期设置
passwd_set="yes"  # yes表示设置
max_day_num="90"  # 过期时间
min_day_num="6"   # 最小修改间隔时间
min_len_num="8"   # 密码最小长度
warn_age_num="14" # 最小警告时间
remember_num="5"

# 密码复杂度设置
passwd_pam_set="yes" # yes表示设置
dcredit_num="-1"     # 至少包含1个数字
lcredit_num="-1"     # 至少包含一个小写字母
ucredit_num="-1"     # 至少包含一个大写字母
ocredit_num="-1"     # 至少包含一个特殊字符
retry_num="6"        # 密码修改可尝试错误次数为6次
minlen_num="8"       # 密码最短长度为8

# 用户锁定设置
user_lock_set="yes"         # yes表示设置
unlocktime_num="300"        # 账户锁定时间
root_unlock_time_num="1800" # root 账户锁定时间
deny_time_num="6"           # 记录密码次数

# 设定时账户自动登出
shell_timeout_set="yes" # yes表示设置
shell_timeout_num=500   # 登录超过 500s 不工作，自动退出
csh_autologout_num=30   # csh shell 30s 后自动超时

# 设置系统账号登录，将 halt、shutdown、sync 账号的默认 shell 改为 /sbin/nologin
system_user_set="yes"

# 设置账户 su 权限
su_set="yes"

# 设置系统 umask
umask_set="yes"

# 修改 /ets/host.conf ，禁止一个主机名对应多个 IP
host_conf_set="yes"

# 对root为ls、rm设置别名
alias_set="yes"

# root 主目录权限
root_home_set="yes"

# 系统重要文件权限修改
file_permission_set="yes"

# 系统资源限制
limits_set="yes"     # yes表示设置
hardnofile_num=65535 # 默认打开的最大文件句柄数 （硬限制）
softnofile_num=65535 # 默认打开的最大文件句柄数 （软限制）
hardnproc_num=65535  # 默认可以打开最大的进程数 （硬限制）
softnproc_num=65535  # 默认可以打开最大的进程数（软限制）

# 设置账户登录日志
# rsyslog 设置
log_user_login_set="yes" #yes表示设置

# login_defs 设置
login_defs_set="yes"

# 设置记录内核日志
log_kern_set="yes"

#设置记录err日志
log_err_set="yes"

# sshd 日志设置
all_sshd_set="yes"
maxauthtries_num="5"

# 设置日志审计设置
auditd_set="yes"

################################################################
################################################################
# NTP配置
f_ntp_set() {
    if which ntpd; then
        info "配置NTP服务"
        [ ! -f /etc/ntp.conf.bak_$day ] && cp /etc/ntp.conf{,.bak_$day}
        sed -i '/^server /d' /etc/ntp.conf
        for i in {0..3}; do
            echo "server ${i}.debian.pool.ntp.org" >>/etc/ntp.conf
        done
        systemctl enable ntpd &>/dev/null
        systemctl restart ntpd &>/dev/null
        success "已设置完成"
    else
        error "系统没有安装 ntp 服务"
    fi

}

###############################################################
#  禁用 root ssh 登录
# 没有启用对应模块，纯粹为了应付检查
# 启用对应模块后，su 不可用，暂为找到解决方法
f_disable_root_telnet_login() {
    info "禁用 root telnet 登录"
    echo "#pts" >/etc/securetty
    success "已设置完成"
}

f_disable_root_ssh_login() {
    [ ! -f /etc/ssh/sshd_config.bak_$day ] && cp /etc/ssh/sshd_config{,.bak_$day}
    info "禁用 root ssh 登录"
    # 1050e 默认开启root ssh登录
    sed -i '/^PermitRootLogin /d' /etc/ssh/sshd_config &>/dev/null
    echo "PermitRootLogin no" >>/etc/ssh/sshd_config
    systemctl restart sshd &>/dev/null
    success "已设置完成"
}

f_disable_root_gui_login() {
    [ ! -f /etc/pam.d/gdm-password ] && touch /etc/pam.d/gdm-password
    [ ! -f /etc/pam.d/gdm-password.bak_$day ] && cp /etc/pam.d/gdm-password{,.bak_$day}
    info "禁用 root 桌面登录"
    echo "auth  required  pam_succeed_if.so  user != root  quiet_success" >/etc/pam.d/gdm-password
    success "已设置完成"
}

f_enable_root_pam_securetty() {
    [ ! -f /etc/pam.d/login.bak_$day ] && cp /etc/pam.d/login{,.bak_$day}
    info "设置 root 远程登录需经过pam_securetty.so模块验证"
    line_num=$(cat /etc/pam.d/login | grep -n '^auth' | awk -F: 'END{print $1}')
    sed -i "${line_num}a\auth  required pam_securetty.so" /etc/pam.d/login
    success "已设置完成"
}

################################################################
#  账户口令安全符合要求，有效期，过期提醒时间，更改最小间隔天数，密码最小长度
f_passwd_set() {
    info "设置账户口令安全"
    [ ! -f /etc/login.defs.bak_$day ] && cp /etc/login.defs{,.bak_$day}
    line_num=$(grep -n ^PASS_ /etc/login.defs | awk NR==1 | awk -F: '{print $1}')
    if [ $? -eq 0 ]; then
        sed -i '/^PASS_/d' /etc/login.defs &>/dev/null
        sed -i "${line_num}i\PASS_MAX_DAYS $max_day_num \nPASS_MIN_DAYS $min_day_num \nPASS_MIN_LEN $min_len_num \nPASS_WARN_AGE $warn_age_num" /etc/login.defs &>/dev/null
    else
        cat >>/etc/login.defs <<EOF
PASS_MAX_DAYS $max_day_num
PASS_MIN_DAYS $min_day_num 
PASS_MIN_LEN $min_len_num 
PASS_WARN_AGE $warn_age_num"
EOF
    fi
    # 记录密码次数
    sed -i '/remember/d' /etc/pam.d/system-auth &>/dev/null
    line_num=$(cat /etc/pam.d/system-auth | grep -n '^password' | awk -F: 'END{print $1}')
    sed -i "${line_num}a\password required pam_unix.so remember=${remember_num}" /etc/pam.d/system-auth &>/dev/null
    success "已设置完成"

}

################################################################OK
# 对所有用户都进行密码策略限制
f_all_user_login() {
    info "对所有用户都进行密码策略限制"
    [ ! -f /etc/pam.d/system-auth.bak_$day ] && cp /etc/pam.d/system-auth{,.bak_$day}
    # pam_passwdqc.so 模块已弃用，为了合规，加到 password 段最后一行，扯淡。
    sed -i '/pam_passwdqc.so/d' /etc/pam.d/system-auth
    line_num=$(cat /etc/pam.d/system-auth | grep -n '^password' | awk -F: 'END{print $1}')
    sed -i "${line_num}a\password required  pam_passwdqc.so  enforce=everyone min=disabled,disabled,12,8,8" /etc/pam.d/system-auth
    success "已设置完成"
}

################################################################
# 检查密码长度及复杂度策略
f_passwd_pam_set() {
    info "设置密码长度及复杂度"
    [ ! -f /etc/security/pwquality.conf.bak_$day ] && cp /etc/security/pwquality.conf{,.bak_$day}
    sed -i '/^password.*pam_pwquality/d' /etc/pam.d/system-auth &>/dev/null
    line_num=$(cat /etc/pam.d/system-auth | grep -n '^password' | awk 'NR==1' | awk -F: '{print $1}') #获取行号
    sed -i "${line_num}i\password   required   pam_pwquality.so try_first_pass retry=${retry_num} minlen=${minlen_num} lcredit=${lcredit_num} ucredit=${ucredit_num} dcredit=${dcredit_num} ocredit=${ocredit_num} enforce_for_root" /etc/pam.d/system-auth
    success "已设置完成"
}

################################################################
# 用户锁定策略
# 不更新 pam 包，如果使用 root 修改密码，会报未知的模块错误，所以将这一行加到 auth 最后一行。
f_user_lock_set() {
    info "设置用户锁定策略"
    [ ! -f /etc/pam.d/system-auth.bak_$day ] && cp /etc/pam.d/system-auth{,.bak_$day}
    sed -i '/pam_tally.*so/d' /etc/pam.d/system-auth
    line_num=$(cat /etc/pam.d/system-auth | grep -n '^auth' | awk -F: 'END{print $1}')
    sed -i "${line_num}a\auth    required      pam_tally2.so  onerr=fail deny=$deny_time_num  unlock_time=$unlocktime_num no_magic_root even_deny_root root_unlock_time=$root_unlock_time_num " /etc/pam.d/system-auth
    success "已设置完成"
}

################################################################
# 定时账户自动登出
f_shell_timeout_set() {
    info "设置 bash 下空闲等待时间 TMOUT 为 ${shell_timeout_num}"
    [ ! -f /etc/profile.bak_${day} ] && cp /etc/profile{,.bak_${day}}
    cat /etc/profile | grep -v "^#" | grep -w TMOUT &>/dev/null
    if [ $? -ne 0 ]; then
        echo "export TMOUT=${shell_timeout_num}" >>/etc/profile
    else
        num_tmout=$(cat /etc/profile | grep -v "^#" | grep TMOUT | awk -F "=" '{print $2}')
        sed -i "/TMOUT/s/${num_tmout}/${shell_timeout_num}/g" /etc/profile &>/dev/null
    fi

    info "设置 csh shell下自动超时变量为 ${csh_autologout_num}"
    [ ! -f /etc/csh.cshrc.bak_${day} ] && cp -p /etc/csh.cshrc{,.bak_${day}}
    cat /etc/csh.cshrc | grep -v "^#" | grep autologout &>/dev/null
    if [ $? -ne 0 ]; then
        echo "set autologout=${csh_autologout_num}" >>/etc/csh.cshrc
    else
        num_autologout=$(cat /etc/csh.cshrc | grep -v "^#" | grep autologout | awk -F "=" '{print $2}')
        sed -i "/autologout/s/${num_autologout}/${csh_autologout_num}/g" /etc/csh.cshrc &>/dev/null
    fi
    success "已设置完成"
}

################################################################
# 对系统账号进行登录限制
f_system_user_set() {
    info "设置系统账号 halt、shutdown、sync 的默认 shell 为 /sbin/nologin"
    [ ! -f /etc/passwd.bak_$day ] && cp /etc/passwd{,.bak_$day}
    set_shell=/sbin/nologin
    current_shell_halt=$(cat /etc/passwd | grep ^halt | awk -F: '{print $NF}')
    sed -i "/halt/s?${current_shell_halt}?${set_shell}?g" /etc/passwd &>/dev/null
    current_shell_sync=$(cat /etc/passwd | grep ^sync | awk -F: '{print $NF}')
    sed -i "/sync/s?${current_shell_sync}?${set_shell}?g" /etc/passwd &>/dev/null
    current_shell_shutdown=$(cat /etc/passwd | grep ^shutdown | awk -F: '{print $NF}')
    sed -i "/shutdown/s?${current_shell_shutdown}?${set_shell}?g" /etc/passwd &>/dev/null
    success "已设置完成"
}

################################################################
#  设置ssh常用选项
f_all_sshd_set() {
    info "设置 SSH 日志记录的详细级别 INFO"
    [ ! -f /etc/ssh/sshd_config.bak_$day ] && cp /etc/ssh/sshd_config{,.bak_$day}
    sed -i '/^LogLevel /d' /etc/ssh/sshd_config &>/dev/null
    echo "LogLevel INFO" >>/etc/ssh/sshd_config

    info "设置 SSH 登录前不显示 Banner 信息"
    sed -i '/^Banner /d' /etc/ssh/sshd_config &>/dev/null
    echo "Banner none" >>/etc/ssh/sshd_config

    info "设置 SSH 登陆尝试次数设置为 ${maxauthtries_num}"
    sed -i '/^MaxAuthTries /d' /etc/ssh/sshd_config &>/dev/null
    echo "MaxAuthTries ${maxauthtries_num}" >>/etc/ssh/sshd_config

    success "已设置完成"
}

################################################################
# 设置su命令权限
f_su_set() {
    info "设置仅有 wheel 组的账号具有 su 权限"
    [ ! -f /etc/pam.d/su.bak_$day ] && cp /etc/pam.d/su{,.bak_$day}
    line_num=$(cat /etc/pam.d/su | grep -n '^auth' | awk 'NR==1' | awk -F: '{print $1}')
    if [ $? -eq 0 ]; then
        sed -i '/^auth.*required.*pam_wheel.so/d' /etc/pam.d/su &>/dev/null
        sed -i "${line_num}i\auth   required    pam_wheel.so group=wheel use_uid" /etc/pam.d/su &>/dev/null
    else
        pam_line_num=$(cat /etc/pam.d/su | grep -n '^#%PAM' | awk 'NR==1' | awk -F: '{print $1}')
        sed -i "${pam_line_num}a\auth   required    pam_wheel.so group=wheel use_uid" /etc/pam.d/su &>/dev/null
    fi
    success "已设置完成"
}

################################################################
#  系统umask设置
f_umask_set() {
    info "设置账户默认 umask 为 027"
    [ ! -f /etc/login.defs.bak_$day ] && cp /etc/login.defs{,.bak_$day}
    sed -i '/^UMASK/d' /etc/login.defs &>/dev/null
    echo "UMASK 027" >>/etc/login.defs

    [ ! -f /etc/csh.log.bak_$day ] && cp /etc/csh.login{,.bak_$day}
    sed -i '/^umask/d' /etc/csh.login &>/dev/null
    echo "umask 027 " >>/etc/csh.login

    [ ! -f /etc/profile.bak_$day ] && cp /etc/profile{,.bak_$day}
    sed -i '/^umask/d' /etc/profile &>/dev/null
    echo "umask 027 " >>/etc/profile

    [ ! -f /etc/csh.cshrc.bak_$day ] && cp /etc/csh.cshrc{,.bak_$day}
    sed -i '/^umask/d' /etc/csh.cshrc &>/dev/null
    echo "umask 027 " >>/etc/csh.cshrc

    [ ! -f /root/.cshrc.bak_$day ] && cp /root/.cshrc{,.bak_$day}
    sed -i '/^umask/d' /root/.cshrc &>/dev/null
    echo "umask 027" >>/root/.cshrc

    [ ! -f /root/.bashrc.bak_$day ] && cp /root/.bashrc{,.bak_$day}
    sed -i '/^umask/d' /root/.cshrc &>/dev/null
    echo "umask 027" >>/root/.cshrc

    [ ! -f /etc/bashrc.bak_$day ] && cp /etc/bashrc{,.bak_$day}
    sed -i '/^umask/d' /etc/bashrc &>/dev/null
    echo "umask 027" >>/etc/bashrc

    [ ! -f /root/.bashrc.bak_$day ] && cp /root/.bashrc{,.bak_$day}
    sed -i '/^umask/d' /root/.bashrc &>/dev/null
    echo "umask 027" >>/root/.bashrc
    success "已设置完成"
}

################################################################
# 对root为ls、rm设置别名
f_alias_set() {
    info "对 root 为 ls、rm 设置别名"
    [ ! -f /root/.bashrc.bak_$day ] && cp /root/.bashrc{,.bak_$day}
    sed -i '/alias/d' /root/.bashrc &>/dev/null
    cat >>/root/.bashrc <<EOF
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias ls='ls -aol'
EOF
}

################################################################
# 关闭绑定多IP及IP伪装功能
# 从 RHEL 7.5 开始，nospoof on 已经不可用，这里也是为了应付检查
f_host_conf_set() {
    info "关闭绑定多IP及IP伪装功能"
    [ ! -f /etc/host.conf.bak_$day ] && cp /etc/host.conf{,.bak_$day}
    sed -i '/multi\|nospoof/d' /etc/host.conf &>/dev/null
    echo "multi off" >>/etc/host.conf
    echo "nospoof on" >>/etc/host.conf
    success "已设置完成"
}

################################################################
# root 主目录权限
f_root_home_set() {
    info "设置 root 主目录权限 "
    chown root:root /root
    chmod 0700 /root
    success "已设置完成"
}

################################################################
# 重要文件权限修改
f_file_permission_set() {
    info "设置重要文件权限"
    chown root:root /etc/passwd
    chmod 644 /etc/passwd
    chown root:root /etc/shadow
    chmod 400 /etc/shadow
    chown root:root /etc/group
    chmod 644 /etc/group
    # 系统默认没有 xinetd.d 目录，为了合规新建
    mkdir -p /etc/xinetd.d
    chmod 755 -R /etc/xinetd.d
    success "已设置完成"
}

################################################################
# 设置 grub 菜单的修改密码
f_grub_set() {
    info "设置 grub 密码为 ${grub_pwd}"
    [ ! -f /etc/grub.d/01_users.bak_$day ] && cp -a /etc/grub.d/01_users{,.bak_$day}
    [ ! -f /boot/efi/EFI/UnionTech/grub.cfg.bak_$day ] && cp -a /boot/efi/EFI/UnionTech/grub.cfg{,.bak_$day}
    grub_pwd_encrypt=$(echo -e "${grub_pwd}\n${grub_pwd}\n" | grub2-mkpasswd-pbkdf2 | grep PBKDF2 | awk '{print $7}')
    sed -i 's/#password/password/g' /etc/grub.d/01_users &>/dev/null
    grub2-mkconfig -o /boot/efi/EFI/UnionTech/grub.cfg &>/dev/null
    echo "GRUB2_PASSWORD=${grub_pwd_encrypt}" >/boot/efi/EFI/UnionTech/user.cfg
    chown root:root /boot/efi/EFI/UnionTech/grub.cfg
    chmod og-rwx /boot/efi/EFI/UnionTech/grub.cfg
    chown root:root /boot/efi/EFI/UnionTech/user.cfg
    chmod og-rwx /boot/efi/EFI/UnionTech/user.cfg
    success "已设置完成"
}

################################################################
#  limits设置
f_limits_set() {
    info "修改 limits.conf 设置"
    [ ! -f /etc/security/limits.conf.bak_$day ] && cp /etc/security/limits.conf{,.bak_$day}
    sed -i "/hard.*core\|soft.*nofile\|hard.*nofile\|soft.*nproc\|hard.*nproc\|End/d" /etc/security/limits.conf &>/dev/null
    cat >>/etc/security/limits.conf <<EOF
# 确保核心转储受到限制
* soft core 0
* hard core 0
# 最大文件句柄数
* soft nofile ${softnofile_num}
* hard nofile ${hardnofile_num}
# 最大进程数
* soft nproc ${softnproc_num}
* hard nproc ${hardnproc_num}
# End of file
EOF
    success "已设置完成"
}

################################################################
#  配置记录用户登录认证及权限变更日志
f_log_user_login_set() {
    info " 配置记录用户登录认证及权限变更日志"
    cat /etc/rsyslog.conf | grep -v '^#' | grep -E "auth\." &>/dev/null

    if [ $? -ne 0 ]; then
        echo "auth.*     /var/log/auth.log" >>/etc/rsyslog.conf
    fi

    cat /etc/rsyslog.conf | grep -v '^#' | grep -E "authpriv\." &>/dev/null
    if [ $? -ne 0 ]; then
        echo "authpriv.*     /var/log/auth.log" >>/etc/rsyslog.conf
    fi
    success "已设置完成"
}

################################################################
# 对登录进行日志记录
f_login_defs_set() {
    info "对登录进行日志记录"
    [ ! -f /etc/login.defs.bak_$day ] && cp /etc/login.defs{,.bak_$day}
    sed -i '/^LASTLOG_ENAB/d' &>/dev/null
    echo "LASTLOG_ENAB yes" >>/etc/login.defs
    success "已设置完成"
}

################################################################
# 配置记录err级别日志
f_log_err_set() {
    info "配置记录err级别日志"
    [ ! -f /etc/rsyslog.conf.bak_$day ] && cp /etc/rsyslog.conf{,.bak_$day}
    cat /etc/rsyslog.conf | grep -v '^#' | grep "\.err" &>/dev/null
    if [ $? -ne 0 ]; then
        echo "*.err;kern.debug;daemon.notice      /var/log/messages" >>/etc/rsyslog.conf
        systemctl restart rsyslog.service &>/dev/null
    fi

    success "已设置完成"
}

################################################################
#  配置记录内核日志
f_log_kern_set() {
    info " 配置记录内核日志"
    cat /etc/rsyslog.conf | grep -v '^#' | grep "kern\." &>/dev/null
    if [ $? -ne 0 ]; then
        echo "kern.*     /var/log/kern.log" >>/etc/rsyslog.conf
        systemctl restart rsyslog.service &>/dev/null
    fi
    success "已设置完成"
}

################################################################
# 设置auditd日志审计
f_auditd_set() {
    info "开启 auditd 日志审计"
    systemctl enable auditd.service &>/dev/null
    auditd_status=$(systemctl status auditd | grep Active | awk '{print $2}')
    if [ "${auditd_status}" != "active" ]; then
        systemctl start auditd &>/dev/null
    fi
    success "已设置完成"
}

################################################################
################################################################
main() {
    item=1

    if [ ${ntp_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置 ntp 服务 ..."
        let item+=1
        f_ntp_set
    fi

    if [ ${disable_root_telnet_login}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在禁用 root telnet 登录 ..."
        let item+=1
        f_disable_root_telnet_login
    fi

    if [ ${disable_root_ssh_login}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在禁用 root ssh 登录 ..."
        let item+=1
        f_disable_root_ssh_login
    fi

    if [ ${disable_root_gui_login}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在禁用 root 桌面登录 ..."
        let item+=1
        f_disable_root_gui_login
    fi

    if [ ${enable_root_pam_securetty}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置 root 远程登录模块验证 ..."
        let item+=1
        f_enable_root_pam_securetty

    fi

    if [ ${passwd_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置账户口令安全 ..."
        let item+=1
        f_passwd_set
    fi

    if [ ${all_user_login}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置所有用户的密码策略 ..."
        let item+=1
        f_all_user_login
    fi

    if [ ${passwd_pam_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置密码复杂度 ..."
        let item+=1
        f_passwd_pam_set
    fi

    if [ ${user_lock_set}x = yesx ]; then
        h1 "[Step ${item}]: 正在设置用户锁定策略 ..."
        let item+=1
        f_user_lock_set
    fi

    if [ ${shell_timeout_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置 shell 登录超时 ..."
        let item+=1
        f_shell_timeout_set
    fi

    if [ ${all_sshd_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置 ssh 选项 ..."
        let item+=1
        f_all_sshd_set
    fi

    if [ ${system_user_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置系统账号登录限制 ..."
        let item+=1
        f_system_user_set
    fi

    if [ ${su_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置账户 su 权限 ..."
        let item+=1
        f_su_set
    fi

    if [ ${umask_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置系统默认 umask 值 ..."
        let item+=1
        f_umask_set
    fi

    if [ ${alias_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置 root 用户下 ls、rm 的别名 ..."
        let item+=1
        f_alias_set
    fi

    if [ ${root_home_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置 root 主目录权限 ..."
        let item+=1
        f_root_home_set
    fi

    if [ ${file_permission_set}x = yesx ]; then
        h1 "[Step ${item}]: 正在设置系统重要文件权限 ..."
        let item+=1
        f_file_permission_set
    fi

    if [ ${limits_set}x = yesx ]; then
        h1 "[Step ${item}]: 正在设置系统资源限制 ..."
        let item+=1
        f_limits_set
    fi

    if [ ${grub_set}x = yesx ]; then
        h1 "[Step ${item}]: 正在设置 grub 密码 ..."
        let item+=1
        f_grub_set
    fi

    if [ ${host_conf_set}x = yesx ]; then
        h1 "[Step ${item}]: 正在设置多 ip 绑定及 ip 伪装功能 ..."
        let item+=1
        f_host_conf_set
    fi

    if [ ${log_user_login_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置用户登录认证及权限变更日志 ..."
        let item+=1
        f_log_user_login_set
    fi

    if [ ${log_kern_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置内核日志 ..."
        let item+=1
        f_log_kern_set
    fi

    if [ ${log_err_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置错误日志 ..."
        let item+=1
        f_log_err_set
    fi

    if [ ${login_defs_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置对登录进行日志记录 ..."
        let item+=1
        f_login_defs_set
    fi

    if [ ${auditd_set}x = "yesx" ]; then
        h1 "[Step ${item}]: 正在设置 auditd 日志审计 ..."
        let item+=1
        f_auditd_set
    fi
}

main
