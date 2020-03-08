#!/ush/bin/env bash

tmpfiles_d="/usr/lib/tmpfiles.d"
dir_fpm_socket="/var/run/php-fpm"

web_us="nginx"
web_gr="nginx"

php_fpm_tmp_orig=`cat $tmpfiles_d/php-fpm.conf`
php_fpm_tmp="d $dir_fpm_socket 0755 $web_us $web_gr"

dir_php="/etc/php"
dir_fpm=`ls $dir_php | grep fpm`

nginx_path="/etc/nginx"
nginx_available="$nginx_path/sites-available"
nginx_enabled="$nginx_path/sites-enable"

nginx_log="/var/log/nginx"
nginx_cert="/etc/ssl/nginx"

dh_cert_bit="4096"
host_cert_bit="2048"

days_cert="3650"

mail_adm="adm@domain"

web_path="/var/www/localhost/htdocs"

tmp_files(){

if [[ "$php_fpm_tmp_orig" == "$php_fpm_tmp" ]] ; then

        echo
        echo "Verify dirs from php socket OK"
        echo

    else

        echo
        echo "Verify dirs from php socket failed"
        echo

        echo $php_fpm_tmp > $tmpfiles_d/php-fpm.conf

fi

}

dir_socket(){

if [[ -z $dir_fpm_socket ]] ; then

	mkdir -pv $dir_fpm_socket
	chown $web_us:$web_gr $dir_fpm_socket 

    else
    	
	chown $web_us:$web_gr $dir_fpm_socket

fi

}

read_info(){

echo
read -p "Please enter hostname from web :  " host
echo

echo
read -p "Please enter domain from web :  " domain
echo

echo
read -p "Please enter dns server :  " dns_serv
echo

}

create_php_poll(){

cat <<EOF> $dir_php/$dir_fpm/fpm.d/$host.conf
[monitor]

;user = nginx
;group = nginx
listen = $dir_fpm_socket/$host.socket

pm = ondemand 
;pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.process_idle_timeout = 300
pm.max_requests = 250

EOF

}

nginx_include(){

mv $nginx_path/nginx.conf $nginx_path/nginx.conf.
sed '$d' $nginx_path/nginx.conf. > $nginx_path/nginx.conf
rm $nginx_path/nginx.conf.

cat <<EOF>>$nginx_path/nginx.conf
include /etc/nginx/sites-enabled/*.conf;

}

EOF

}

nginx_web_host_create_dir(){

if [[ -z $nginx_available ]] ; then

	mkdir $nginx_available $nginx_enabled 

    else

    	echo

fi

}

nginx_web_host_create_host(){

cat <<EOF>$nginx_available/host.conf

server {
	listen 80;
	server_name $host.$domain;
	return 301 https://\$server_name\$request_uri;
}

server {
	listen 443 ssl http2;
	server_name  $host.$domain;
	root   $web_path/$host;
	index index.php;

	access_log $nginx_log/$host'_access_log' main buffer=32k;
	error_log $nginx_log/$host'_error_log' error ;

	#    auth_basic "Who is you? Enter the password!!!";
	#    auth_basic_user_file /file/auth;

	client_max_body_size 8m;
	proxy_read_timeout 300;
	proxy_send_timeout 300;
	proxy_connect_timeout 300;
	send_timeout 300;

	include ssl.conf;

	ssl_certificate $nginx_ssl/$host.$domain.crt;
	ssl_certificate_key $nginx_ssl/$host.$domain.key;

	location ~* /\.ht { deny all; }
	location ~* ^/(api|include)/? { deny all; }

	location ~ \.php$ {
        	fastcgi_pass unix:$dir_fpm_socket/$host.socket;
		fastcgi_index  index.php;
	        fastcgi_param  SCRIPT_FILENAME  \$document_root\$fastcgi_script_name;
		include         $nginx_path/fastcgi_params;
		fastcgi_read_timeout 300;
    	}
}

EOF

}

nginx_web_host_enable(){

ln -s $nginx_available/$host.conf $nginx_enabled/$host.conf

}

nginx_ssl_conf(){

nginx_ssl_file="$nginx_path/ssl.conf"

if [[ -z $nginx_ssl_file ]] ; then

	nginx_ssl_conf_create
fi

}

nginx_ssl_conf_create(){
cat <<EOF>$nginx_ssl_file
ssl_session_cache shared:SSL:10m;
ssl_session_timeout  5m;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'HIGH:!aNULL:EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA256:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA256:EECDH+aRSA+SHA256:EECDH:EDH+aRSA:RC4:ADH:!NULL:!aNULL:!eNULL:!EXPORT:!LOW:!MD5:3DES:!PSK:!SRP:!DSS:!SEED:!CAMELLIA:!IDEA:!SSLv2';
ssl_prefer_server_ciphers on;
ssl_ecdh_curve auto;
ssl_stapling on;
ssl_stapling_verify on;

add_header Strict-Transport-Security "max-age=31536000";
ssl_dhparam $nginx_path/dh.pem;
keepalive_timeout    70;

add_header Strict-Transport-Security "max-age=15552000; includeSubDomains";
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options "SAMEORIGIN";
add_header X-XSS-Protection "1; mode=block";
add_header X-Robots-Tag none;
add_header X-Download-Options noopen;
add_header X-Permitted-Cross-Domain-Policies none;

resolver $dns_serv ipv6=off  valid=600s;
resolver_timeout 5s;

EOF

}

php_edit_unit(){

unit_fpm=`systemctl list-unit-files | grep fpm | awk '{print $1}'`
unit_file=`echo $unit_fpm | xargs systemctl cat | grep '.service' | awk '{print $2}'`

osn_unit_file=`echo $unit_fpm | xargs systemctl cat | sed '/Install\|WantedBy/d'`
dop_unit_install=`echo $unit_fpm | xargs systemctl cat | grep 'Install\|WantedBy'`

tmp_unit_file="/tmp/php-fpm.service"

cat <<EOF>$tmp_unit_file
$osn_unit_file
User=nginx
Group=nginx

$dop_unit_install

EOF

mv $tmp_unit_file $unit_file

systemctl daemon-reload

}

gen_dh_cert(){

dh_file="$nginx_path/dh.pem"

if [[ -z $dh_file ]] ; then

	openssl dhparam -out $dh_file $dh_cert_bit

fi

}

gen_host_cert(){

openssl req -new -newkey rsa:$host_cert_bit -nodes -keyout $nginx_ssl/$host.$domain.key -x509 -days $days -subj "/C=RU/ST=Arkh/L=Arkh/O=OAO/OU=Sales/CN=$host/emailAddress=$mail_adm (mailto:$mail_adm)" -out $nginx_ssl/$host.$domain.crt

chown $web_us:$web_gr -R $nginx_ssl/$host.$domain.*
chmod 600 $nginx_ssl/$host.$domain.*

}

list_avail(){

conf_avail=`ls $nginx_available`

echo
echo "List nginx available host"
echo

echo $conf_avail
echo

}

list_enabled(){

conf_enabled=`ls $nginx_enabled`

echo
echo "List nginx enabled host"
echo

echo $conf_enabled
echo

}

disable_web_host(){

echo

list_enabled

echo
read -p "Enter name host from disabled (example: my.domain.com) :   " $dis_host
echo

echo "Desable web host =  $dis_host"
echo

rm -v $nginx_enabled/$dis_host.conf

echo

}

remove_web_host(){

echo

list_enabled

echo
read -p "Enter name host from disabled (example: my.domain.com) :   " $remove_host
echo

echo "Remove web host =  $dis_host"
echo

rm -v {$nginx_enabled,$nginx_available}/$dis_host.conf

echo

}


menu_config(){

while :
do
clear
echo
echo
echo -e "\t\t\t\e[1;30;1;32m  ,--------------------------------------------,\e[0m"
echo -e "\t\t\t\e[1;30;1;32m /\t\t\t\t\t\t\ \e[0m\e[0m"
echo -e "\t\t\t\e[1;30;1;32m (\e[0m\e[1;30;1;31m\t\tMenu create configuration web host\t\t\t\e[0m\e[1;30;1;32m)\e[0m"
echo -e "\t\t\t\e[1;30;1;32m \ \t\t\t\t\t\t/\e[0m\e[0m "
echo -e "\t\t\t\e[1;30;1;32m  '--------------------------------------------'\e[0m\e[0m"
echo
echo
echo -e "\t1. Prepere from create web hosts"
echo -e "\t2. Create web host"
echo -e "\t3. List avaibaile web hosts"
echo -e "\t4. List enabled web hosts"
echo =e "\t5. Disable web host"
echo -e "\t7. Remove web host"
echo -e "\t8. List current php-fpm polls"
echo
echo -e "\t0. Back"
echo
echo -en "\t\t" ; read -p "Please enter your choice :  " -n 1 config_opt
echo
echo
case $config_opt in

1)
        echo
        echo -e "\t1. Prepere from create web hosts"
        echo
        tmp_files
	dir_socket
	php_edit_unit
	nginx_include
	nginx_web_host_create_dir
	nginx_ssl_conf;;
2)
        echo
        echo -e "\t2. Create web host"
        echo
        read_info
	create_php_poll
	nginx_web_host_create_host
	nginx_ssl_conf_create
	gen_dh_cert
	gen_host_cert
	nginx_web_host_enable;;
0)
        break
        ;;
*)
        clear

echo
echo -en "\t\tSelect menu point";;

esac

echo
echo
echo -en "\n\n\t\t\t" ; read -p "Please any key " -n 1 line
echo

done

clear

}

menu_enable(){

while :
do
clear
echo
echo
echo -e "\t\t\t\e[1;30;1;32m  ,--------------------------------------------,\e[0m"
echo -e "\t\t\t\e[1;30;1;32m /\t\t\t\t\t\t\ \e[0m\e[0m"
echo -e "\t\t\t\e[1;30;1;32m (\e[0m\e[1;30;1;31m\t\tTools Menu\t\t\t\e[0m\e[1;30;1;32m)\e[0m"
echo -e "\t\t\t\e[1;30;1;32m \ \t\t\t\t\t\t/\e[0m\e[0m "
echo -e "\t\t\t\e[1;30;1;32m  '--------------------------------------------'\e[0m\e[0m"
echo
echo
echo -e "\t1. Create LVM Thin"
echo -e "\t2. Cleaning disk from install system"
echo
echo -e "\t0. Back"
echo
echo -en "\t\t" ; read -p "Please enter your choice :  " -n 1 tools_opt
echo
echo
case $tools_opt in

1)
        echo
        echo -e "\t1. Create LVM Thin"
        echo
        lvm_thin;;
2)
        echo
        echo -e "\t2. Cleaning disk from install system"
        echo
        clean_disk;;
0)
        break
        ;;
*)
        clear

echo
echo -en "\t\tSelect menu point";;

esac

echo
echo
echo -en "\n\n\t\t\t" ; read -p "Please any key " -n 1 line
echo

done

clear 

}

while :
do
clear
echo
echo
echo -e "\t\t\t\e[1;30;1;32m  ,--------------------------------------------,\e[0m"
echo -e "\t\t\t\e[1;30;1;32m /\t\t\t\t\t\t\ \e[0m\e[0m"
echo -e "\t\t\t\e[1;30;1;32m (\e[0m\e[1;30;1;31m\tThis script create conf from web host on nginx/php-fpm\t\t\e[0m\e[1;30;1;32m)\e[0m"
echo -e "\t\t\t\e[1;30;1;32m \ \t\t\t\t\t\t/\e[0m\e[0m "
echo -e "\t\t\t\e[1;30;1;32m  '--------------------------------------------'\e[0m\e[0m"
echo
echo
echo -e "\t1. Create configuration "
echo -e "\t2. Enable/Disable configuration "
#echo -e "\t3. "
echo
echo -e "\t0. Exit"
echo
echo -en "\t\t" ; read -p "Please enter your choice :  " -n 1 main_opt
echo
echo
case $main_opt in

0)
        break;;
1)
        menu_config;;
2)
        menu_enable;;
#3)
#        menu_tools;;
*)
        clear

echo
echo -en "\t\tSelect menu point";;

esac
echo

done

clear






