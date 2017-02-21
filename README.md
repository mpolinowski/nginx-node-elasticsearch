# Using NGINX as proxy for your nodejs apps
**We want to set up NGINX with http/2 to serve multiple node apps and an instance of Elasticsearch on a single centOS server**

1. [Useful Links](#1-useful-links)
2. [Install Nginx and Adjust the Firewall](#2-install-nginx-and-adjust-the-firewall)
3. [FirewallD](#3-firewalld)
4. [Create a login](#4-create-a-login)
5. [nginx.conf](#5-nginxconf)
6. [virtual.conf](#6-virtualconf)


### 1 Useful links
___

* [Apache2-Utils](https://kyup.com/tutorials/set-http-authentication-nginx/)
* [SSL Labs](https://www.ssllabs.com/ssltest/)
* [Set up NGINX with http/2](https://www.digitalocean.com/community/tutorials/how-to-set-up-nginx-with-http-2-support-on-ubuntu-16-04)
* [Create a self-signed Certificate](https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-nginx-on-centos-7/)



### 2 Install Nginx and Adjust the Firewall
___

* **Step One** — Nginx is not available in CentOS's default repositories - but we can install it from the EPEL (extra packages for Enterprise Linux) repository.

```
 sudo yum install epel-release
```

* **Step Two** — Next, we can install Nginx.

```
 sudo yum install nginx
```

* **Step Three** — Start the Nginx service and test it inside your browser http://server_domain_name_or_IP/

```
 sudo systemctl start nginx
```

* **Step Four** — Check that the service is up and running by typing:

```
 systemctl status nginx
```

* **Step Five** — You will also want to enable Nginx, so it starts when your server boots:

```
 sudo systemctl enable nginx
```


### 3 FirewallD
___

* **Step One** — Installation

Open ports 80 and 443 in [FirewallD](http://www.firewalld.org/)

To start the service and enable FirewallD on boot:

```
sudo systemctl start firewalld
sudo systemctl enable firewalld
```

To stop and disable it:

```
sudo systemctl stop firewalld
sudo systemctl disable firewalld
```

Check the firewall status. The output should say either running or not running:

```
sudo firewall-cmd --state
```

To view the status of the FirewallD daemon:

```
sudo systemctl status firewalld
```

To reload a FirewallD configuration:

```
sudo firewall-cmd --reload
```

* **Step Two** — Configuration

Add the http/s rule to the permanent set and reload FirewallD.

```
sudo firewall-cmd --zone=public --add-service=https --permanent
sudo firewall-cmd --zone=public --add-service=http --permanent
sudo firewall-cmd --reload
```

Allow traffic / block traffic over ports:

```
sudo firewall-cmd --zone=public --add-port=12345/tcp --permanent
sudo firewall-cmd --zone=public --remove-port=12345/tcp --permanent
```


### 4 Create a login
___

```
sudo htpasswd -c /etc/nginx/.htpasswd USERNAME
New password: xxxxxxxxx
Re-type new password: xxxxxxxxx
```


### 5 nginx.conf

/etc/nginx/nginx.conf

```
user nginx;
worker_processes 8;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;
	gzip on;
	gzip_vary on;
	gzip_proxied any;
	gzip_comp_level 6;
	gzip_buffers 16 8k;
	gzip_http_version 1.1;
	gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;
	# include /etc/nginx/sites-enabled/*;

	# Hide nginx version token
	server_tokens off;

	# Configure buffer sizes
	client_body_buffer_size 16k;
	client_header_buffer_size 1k;
	client_max_body_size 8m;
	large_client_header_buffers 2 1k;

}
```


### 6 virtual.conf

/etc/nginx/conf.d/virtual.conf

Set up virtual server instances for our 2 node/express apps, Elasticsearch and Kibana

```
# redirect http/80 traffic to https/443 for our node apps
server {
       listen         80;
       listen    [::]:80;
       server_name    example.de example2.de;
       return         301 https://$server_name$request_uri;
}

# point to our first node app that is running on port 8888 and accept calls over https://example.de:443
upstream myApp_en {
	# point to the running node
	server 127.0.0.1:8888;
}

server {
	# users using this port and domain will be directed to the node app defined above
	# listen 80 default_server;
	# listen [::]:80 default_server ipv6only=on;
	listen 443 ssl http2 default_server;
	listen [::]:443 ssl http2 default_server;
	# If you want to run more then one node app, they either have to be assigned different web domains (server_name) or ports!
	server_name example.de;

	# Adding the SSL Certificates
    ssl_prefer_server_ciphers on;
	ssl_ciphers EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
	ssl_dhparam /etc/nginx/ssl/dhparam.pem;
	ssl_certificate /etc/nginx/ssl/nginx-selfsigned.crt;
	ssl_certificate_key /etc/nginx/ssl/nginx-selfsigned.key;

	# set the default public directory for your node
	root /opt/myApp_en/build/public;

	# Optimizing Nginx for Best Performance
	ssl_session_cache shared:SSL:5m;
    ssl_session_timeout 1h;

	location / {
    	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    	proxy_set_header Host $http_host;
    	proxy_set_header X-NginX-Proxy true;
    	proxy_http_version 1.1;
    	proxy_set_header Upgrade $http_upgrade;
    	proxy_set_header Connection "upgrade";
    	proxy_max_temp_file_size 0;
		proxy_pass http://myApp_en;
    	proxy_redirect off;
    	proxy_read_timeout 240s;
		# Authentication can be activated during development
		# auth_basic "Username and Password are required";
		# the user login has to be generated
		# auth_basic_user_file /etc/nginx/.htpasswd;
	}

	# use NGINX to cache static resources that are requested regularly
	location ~* \.(css|js|jpg|png|ico)$ {
		expires 168h;
	}
}


# point to our second node app that is running on port 8484 and accept calls over https://example2.de:443
upstream myApp_de {
	# point to the second running node
	server 127.0.0.1:8484;
}

server {
	# users using this port and domain will be directed to the second node app
	# listen 80;
	# listen [::]:8080 ipv6only=on;
	listen 443 ssl http2;
	# The IPv6 address is unique - only one app can use the default port 443!
	listen [::]:444 ssl http2;
	server_name example2.de;

	# adding the SSL Certificates
    ssl_prefer_server_ciphers on;
	ssl_ciphers EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
	ssl_dhparam /etc/nginx/ssl/dhparam.pem;
	ssl_certificate /etc/nginx/ssl/nginx-selfsigned.crt;
	ssl_certificate_key /etc/nginx/ssl/nginx-selfsigned.key;

	# set the default public directory for your second node
	root /opt/myApp_de/build/public;

	# optimizing Nginx for Best Performance
	ssl_session_cache shared:SSL:5m;
    ssl_session_timeout 1h;

	location / {
    	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    	proxy_set_header Host $http_host;
    	proxy_set_header X-NginX-Proxy true;
    	proxy_http_version 1.1;
    	proxy_set_header Upgrade $http_upgrade;
    	proxy_set_header Connection "upgrade";
    	proxy_max_temp_file_size 0;
		proxy_pass http://myApp_de;
    	proxy_redirect off;
    	proxy_read_timeout 240s;
		# auth_basic "Username and Password are required";
		# auth_basic_user_file /etc/nginx/.htpasswd;
	}

	# use NGINX to cache static resources that are requested regularly
	location ~* \.(css|js|jpg|png|ico)$ {
		expires 168h;
	}
}


# point to our Elasticsearch database that is running on port 9200 and accept calls over 8080
upstream elasticsearch {
	# point to the second running node
	server 127.0.0.1:9200;
}

server {
	# users using this port will be directed to Elasticsearch
	listen 8080;
	listen [::]:8080 ipv6only=on;
	server_name SERVER_IP_ADDRESS;

	location / {
    	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    	proxy_set_header Host $http_host;
    	proxy_set_header X-NginX-Proxy true;
    	proxy_http_version 1.1;
    	proxy_set_header Upgrade $http_upgrade;
    	proxy_set_header Connection "upgrade";
    	proxy_max_temp_file_size 0;
		proxy_pass http://elasticsearch;
    	proxy_redirect off;
    	proxy_read_timeout 240s;
		auth_basic "Username and Password are required";
		auth_basic_user_file /etc/nginx/.htpasswd;
	}

}

# point to our Kibana instance that is running on port 5601 and accept calls over 8181
server {
	# users using this port and will be directed to Elasticsearch/Kibana
	listen 8181;
	listen [::]:8181 ipv6only=on;

	server_name SERVER_IP_ADDRESS;

	auth_basic "Restricted Access";
	auth_basic_user_file /etc/nginx/.htpasswd;

	location / {
    	proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;        
	}

}
```
