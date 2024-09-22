# Двухступенчатый VPN (WG+VLESS)

#### Рекомендации
Debian 12 ноды (1 core, 400+mb ram, 3+gb storage, unlimited traffic)

# Настройка enter node
    apt update && sudo apt install -y sshpass git curl unzip wireguard wireguard-tools iptables iptables-persistent wget tcpdump qrencode fail2ban  
    git clone https://github.com/ckaap/wg2vless.git
    cd wg2vless
    touch info.txt
#### Получение данные exit node
    read -p "Введите IP exit node: " IP_EXIT
    echo "IP_EXIT=$IP_EXIT" >> info.txt
    read -p "Введите логин для exit node: " EXIT_USER
    echo "EXIT_USER=$EXIT_USER" >> info.txt
    read -s -p "Введите пароль для exit node: " EXIT_PASSWORD
    echo "EXIT_PASSWORD=$EXIT_PASSWORD" >> info.txt
#### Установка XRAY
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root
#### Включаем проброс трафика
    grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
##### Получаем внешний IP
    export IP_ENTER=$(curl -s https://api.ipify.org)
#### Генерация ключей для сервера и клиента Wireguard
    wg genkey > server_private_key.txt
    wg pubkey < server_private_key.txt > server_public_key.txt
    wg genkey > client_private_key.txt
    wg pubkey < client_private_key.txt > client_public_key.txt
    export WG_SERVER_PRIVATE=$(cat server_private_key.txt)
    export WG_SERVER_PUBLIC=$(cat server_public_key.txt)
    export WG_CLIENT_PUBLIC=$(cat client_public_key.txt)
    export WG_CLIENT_PRIVATE=$(cat client_private_key.txt)
    echo "export WG_CLIENT_PRIVATE=$WG_CLIENT_PRIVATE" >> info.txt
    sed -i \
	-e "s|WG_SERVER_PRIVATE|$WG_SERVER_PRIVATE|g" \
	-e "s|WG_CLIENT_PUBLIC|$WG_CLIENT_PUBLIC|g" \
	enter_node/wg0.conf
    cp enter_node/wg0.conf /etc/wireguard/wg0.conf
    sed -i \
	-e "s|WG_CLIENT_PRIVATE|$WG_CLIENT_PRIVATE|g" \
	-e "s|WG_SERVER_PUBLIC|$WG_SERVER_PUBLIC|g" \
	-e "s|IP_ENTER|$IP_ENTER|g" \
	enter_node/wg_client.conf
#### Запуск WireGuard
    wg-quick up wg0
    systemctl enable wg-quick@wg0.service
    sleep 1
#### Установка tun2socks
    wget -O tun2socks-linux-amd64.zip https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-linux-amd64.zip
    unzip tun2socks-linux-amd64.zip
    chmod +x ./tun2socks-linux-amd64
    mv ./tun2socks-linux-amd64 /usr/local/bin/tun2socks
    rm tun2socks-linux-amd64.zip
    cp enter_node/tun2socks.service /etc/systemd/system/tun2socks.service
    systemctl start tun2socks
    systemctl enable tun2socks
#### Настройка маршрутизации
    iptables -A FORWARD -i wg0 -j ACCEPT
    export INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
    iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
    iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
    netfilter-persistent save
    chmod +x routes.sh
    if [ -f "./routes.sh" ]; then
      chmod +x routes.sh
      ./routes.sh
    else
      echo "Файл routes.sh не найден. Пропускаем этот шаг."
    fi
#### Поиск сайта для маскировки используя RealiTLScanner
	wget -O RealiTLScanner https://github.com/XTLS/RealiTLScanner/releases/download/v0.2.1/RealiTLScanner-linux-64
	chmod +x ./RealiTLScanner
	timeout 30s ./RealiTLScanner -addr $IP_EXIT -port 443 -timeout 5 -out sites.csv
	export XRAY_SITE=$(tail -1 sites.csv | cut -d ',' -f3 | sed 's/^*\.\(.*\)/\1/')
	rm sites.csv RealiTLScanner
	echo "export XRAY_SITE="$XRAY_SITE >> info.txt
#### Генерация XRAY UUID и ключей
	export XRAY_UUID=$(uuidgen)
	echo "export XRAY_UUID=$XRAY_UUID" >> info.txt
#### Генерация приватного и публичного ключа с использованием Xray
	XRAY_KEYS=$(/usr/local/bin/xray x25519)
	export XRAY_PRIVATE=$(echo "$XRAY_KEYS" | grep 'Private' | awk '{print $3}')
	export XRAY_PUBLIC=$(echo "$XRAY_KEYS" | grep 'Public' | awk '{print $3}')
	export XRAY_SHORT=$(echo $XRAY_UUID | sed 's/-//g' | cut -c1-16)
#### Сохранение переменных XRAY в файл
	echo "export XRAY_PRIVATE=$XRAY_PRIVATE" >> info.txt
	echo "export XRAY_PUBLIC=$XRAY_PUBLIC" >> info.txt
	echo "export XRAY_SHORT=$XRAY_SHORT" >> info.txt
#### Вывод для проверки переменных окружения
	echo "IP_EXIT $IP_EXIT"
	echo "IP_ENTER $IP_ENTER"
	echo "XRAY_SITE $XRAY_SITE"
	echo "XRAY_UUID $XRAY_UUID"
	echo "XRAY_PRIVATE $XRAY_PRIVATE"
	echo "XRAY_PUBLIC $XRAY_PUBLIC"
	echo "XRAY_SHORT $XRAY_SHORT"
#### Настройка конфигурации Xray (enter node)
	sed -i \
		-e "s|IP_EXIT|$IP_EXIT|g" \
		-e "s|XRAY_UUID|$XRAY_UUID|g" \
		-e "s|XRAY_SITE|$XRAY_SITE|g" \
		-e "s|XRAY_PUBLIC|$XRAY_PUBLIC|g" \
		-e "s|XRAY_SHORT|$XRAY_SHORT|g" \
		enter_node/config.json
#### Копирование конфигурационного файла и перезапуск Xray
    rm /usr/local/etc/xray/config.json
    cp enter_node/config.json /usr/local/etc/xray/config.json
    systemctl restart xray fail2ban
    sleep 2
# Настройка exit node
    sshpass -p "$EXIT_PASSWORD" ssh -o StrictHostKeyChecking=no $EXIT_USER@$IP_EXIT << EOF
    sudo apt update
    sleep 1
    sudo apt install -y git curl uuid iptables wget tcpdump fail2ban
#### enable port forwarding
    grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    EOF
    sshpass -p "$EXIT_PASSWORD" ssh -o StrictHostKeyChecking=no $EXIT_USER@$IP_EXIT 'bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root'
    sed -i \
	-e "s/XRAY_UUID/$XRAY_UUID/g" \
	-e "s/XRAY_SITE/$XRAY_SITE/g" \
	-e "s/XRAY_PRIVATE/$XRAY_PRIVATE/g" \
	-e "s/XRAY_SHORT/$XRAY_SHORT/g" \
	exit_node/config.json
    sshpass -p "$EXIT_PASSWORD" scp -o StrictHostKeyChecking=no "exit_node/config.json" "$EXIT_USER@$IP_EXIT:/usr/local/etc/xray/config.json"
    sshpass -p "$EXIT_PASSWORD" ssh -o StrictHostKeyChecking=no $EXIT_USER@$IP_EXIT << EOF
    systemctl restart xray fail2ban
    sleep 2
    systemctl status xray
    EOF 
#### Генерация QR
    RED='\033[0;31m'
    NC='\033[0m'
    GREEN='\033[0;32m'
    echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
    qrencode -t ansiutf8 -l L <"enter_node/wg_client.conf"
    echo ""
    echo -e "${GREEN}Your client config file is in enter_node/wg_client.conf"
#### Проверка работы socks
    if [ "$(curl -s -x socks5h://127.0.0.1:20170 eth0.me 2>/dev/null)" = "$IP_EXIT" ]; then
      echo -e "${GREEN}TEST VPN - ON${NC}"
    else
      echo -e "${RED}TEST VPN - OFF${NC}"
    fi
    echo "Скрипт завершен."
# Удалить файлы с данными
    rm -rf wg2vless
    rm ./info.txt
