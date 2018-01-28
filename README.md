# Using NGINX as proxy for your nodejs apps
**We want to set up NGINX with http/2 to serve multiple node apps and an instance of Elasticsearch on a single centOS server**

<!-- TOC -->

- [Using NGINX as proxy for your nodejs apps](#using-nginx-as-proxy-for-your-nodejs-apps)
  - [1 Useful links](#1-useful-links)
  - [2 Install Nginx and Adjust the Firewall](#2-install-nginx-and-adjust-the-firewall)
  - [3 FirewallD](#3-firewalld)
  - [4 Create a login](#4-create-a-login)
  - [5 nginx.conf](#5-nginxconf)
  - [6 virtual.conf](#6-virtualconf)
  - [7 GoDaddy Certs](#7-godaddy-certs)
    - [Generate a CSR and Private Key](#generate-a-csr-and-private-key)
    - [Download your key from GoDaddy](#download-your-key-from-godaddy)
    - [Install Certificate On Web Server](#install-certificate-on-web-server)
  - [8 LetsEncrypt and Certbot](#8-letsencrypt-and-certbot)
    - [Install Certbot on CentOS 7](#install-certbot-on-centos-7)
    - [Run Certbot](#run-certbot)
    - [Setting Up Auto Renewal](#setting-up-auto-renewal)
      - [Systemd](#systemd)
      - [Cron.d](#crond)
    - [TLS-SNI-01 challenge Deactivated](#tls-sni-01-challenge-deactivated)
  - [9 Search Engine Setup and Configuration](#9-search-engine-setup-and-configuration)
    - [Installing Elasticsearch 6.x on CentOS](#installing-elasticsearch-6x-on-centos)
      - [Import the Elasticsearch PGP Key](#import-the-elasticsearch-pgp-key)
    - [Installing from the RPM repository](#installing-from-the-rpm-repository)
      - [Running Elasticsearch with _systemd_](#running-elasticsearch-with-_systemd_)
      - [Checking that Elasticsearch is running](#checking-that-elasticsearch-is-running)
      - [Configuring Elasticsearch](#configuring-elasticsearch)
    - [Installing Kibana 6.x on CentOS](#installing-kibana-6x-on-centos)
      - [Running Kibana with _systemd_](#running-kibana-with-_systemd_)
    - [Install X-Pack](#install-x-pack)
      - [Elasticsearch Security](#elasticsearch-security)
      - [Kibana Security](#kibana-security)
    - [Enabling Anonymous Access](#enabling-anonymous-access)

<!-- /TOC -->


## 1 Useful links
___

* [Apache2-Utils](https://kyup.com/tutorials/set-http-authentication-nginx/)
* [SSL Labs](https://www.ssllabs.com/ssltest/)
* [Set up NGINX with http/2](https://www.digitalocean.com/community/tutorials/how-to-set-up-nginx-with-http-2-support-on-ubuntu-16-04)
* [Create a self-signed Certificate](https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-nginx-on-centos-7/)
* [How To Secure Nginx with Let's Encrypt on CentOS 7](https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-centos-7)
* [Installing Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/install-elasticsearch.html)
* [Installing Kibana](https://www.elastic.co/guide/en/kibana/current/install.html)
* [Installing X-Pack](https://www.elastic.co/downloads/x-pack)



## 2 Install Nginx and Adjust the Firewall
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


## 3 FirewallD
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

Verify open ports:

```
firewall-cmd --list-ports
```

Check the firewall status:

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




## 4 Create a login
___

```
sudo htpasswd -c /etc/nginx/.htpasswd USERNAME
New password: xxxxxxxxx
Re-type new password: xxxxxxxxx
```


## 5 nginx.conf

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
	large_client_header_buffers 4 8k;

}
```


## 6 virtual.conf

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


## 7 GoDaddy Certs

When you ordered a wildcard certificate from goDaddy you will receive two files: Your SSL Certificate with a random name (Ex. 93rfs8dhf834hts.crt) and the GoDaddy intermediate certificate bundle (gd_bundle-g2-g1.crt). Lets install them on our server.


### Generate a CSR and Private Key

Create a folder to put all our ssl certificates:

```
mkdir /etc/nginx/ssl
cd /etc/nginx/ssl
```

Generate our private key, called example.com.key, and a CSR, called example.com.csr:

```
openssl req -newkey rsa:2048 -nodes -keyout example.com.key -out example.com.csr
```

At this point, you will be prompted for several lines of information that will be included in your certificate request. The most important part is the Common Name field which should match the name that you want to use your certificate with — for example, example.com, www.example.com, or (for a wildcard certificate request) [STAR].example.com.


### Download your key from GoDaddy

The files you receive will look something like this:

- 93rfs8dhf834hts.crt
- gd_bundle-g2-g1.crt

Upload both to /etc/nginx/ssl directory and rename the first one to your domain name example.com.cst


### Install Certificate On Web Server

You can use the following command to create a combined file from both GoDaddy files called example.com.chained.crt:

```
cat example.com.crt gd_bundle-g2-g1.crt > example.com.chained.crt
```

And now you should change the access permission to this folder:

```
cd /etc/nginx
sudo chmod -R 600 ssl/
```

To complete the configuration you have to make sure your NGINX config points to the right cert file and to the private key you generated earlier. Add the following lines inside the server block of your NGINX config:

```
# adding the SSL Certificates
  ssl_prefer_server_ciphers on;
  ssl_ciphers EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
	ssl_certificate /etc/nginx/ssl/example.com.chained.crt;
	ssl_certificate_key /etc/nginx/ssl/example.com.key;
```

Always test your configuration first:

```
nginx -t
```

and then reload:

```
service nginx reload
```


## 8 LetsEncrypt and Certbot

### Install Certbot on CentOS 7

**yum install certbot-nginx**

```
Dependencies Resolved

==============================================================================================
 Package                         Arch             Version                Repository      Size
==============================================================================================
Installing:
 python2-certbot-nginx           noarch           0.14.1-1.el7           epel            52 k
Installing for dependencies:
 pyparsing                       noarch           1.5.6-9.el7            base            94 k

Transaction Summary
==============================================================================================
Install  1 Package (+1 Dependent package)

Complete!
```

### Run Certbot

**certbot --nginx -d wiki.instar.fr**

```
Saving debug log to /var/log/letsencrypt/letsencrypt.log
Enter email address (used for urgent renewal and security notices) (Enter 'c' to
cancel):
```

**myemail@email.com**
```
-------------------------------------------------------------------------------
Please read the Terms of Service at
https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf. You must agree
in order to register with the ACME server at
https://acme-v01.api.letsencrypt.org/directory
-------------------------------------------------------------------------------
```

**(A)gree/(C)ancel: A**

```
Starting new HTTPS connection (1): supporters.eff.org
Obtaining a new certificate
Performing the following challenges:
tls-sni-01 challenge for wiki.instar.fr
Waiting for verification...
Cleaning up challenges
Deployed Certificate to VirtualHost /etc/nginx/conf.d/virtual.conf for set(['wiki.instar.fr'])

Please choose whether HTTPS access is required or optional.
-------------------------------------------------------------------------------
1: Easy - Allow both HTTP and HTTPS access to these sites
2: Secure - Make all requests redirect to secure HTTPS access
-------------------------------------------------------------------------------
Select the appropriate number [1-2] then [enter] (press 'c' to cancel): 2
The appropriate server block is already redirecting traffic. To enable redirect anyway, uncomment the redirect lines in /etc/nginx/conf.d/virtual.conf.
-------------------------------------------------------------------------------
Congratulations! You have successfully enabled https://wiki.instar.fr
-------------------------------------------------------------------------------
```

```
IMPORTANT NOTES:
 - Congratulations! Your certificate and chain have been saved at
   /etc/letsencrypt/live/wiki.instar.fr/fullchain.pem. Your cert will
   expire on 2017-12-13. To obtain a new or tweaked version of this
   certificate in the future, simply run certbot again with the
   "certonly" option. To non-interactively renew *all* of your
   certificates, run "certbot renew"
 - Your account credentials have been saved in your Certbot
   configuration directory at /etc/letsencrypt. You should make a
   secure backup of this folder now. This configuration directory will
   also contain certificates and private keys obtained by Certbot so
   making regular backups of this folder is ideal.
```

### Setting Up Auto Renewal


#### Systemd

Go to _/etc/systemd/system/_ and create the following two files

_certbot-nginx.service_
```
[Unit]
Description=Renew Certbot certificates (nginx)
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot-2 renew --deploy-hook "systemctl reload nginx"
```

_certbot-nginx.timer_
```
[Unit]
Description=Renew Certbot certificate (nginx)

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=86400

[Install]
WantedBy=multi-user.target
```

Now activate the service

```
$ systemctl daemon-reload
$ systemctl start certbot-nginx.service  # to run manually
$ systemctl enable --now certbot-nginx.timer  # to use the timer
```


#### Cron.d

Add Certbot renewal to Cron.d in /etc/cron.d - we want to run it twice daily at 13:22 and 04:17:

```
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed

17 4 * * * /usr/bin/certbot-2 renew --quiet
22 13 * * * /usr/bin/certbot-2 renew --quiet
```

### TLS-SNI-01 challenge Deactivated

If you are receiving the following error when trying to add a certificate to your domain:

```
Client with the currently selected authenticator does not support any combination of challenges that will satisfy the CA.
```

Follow the Instructions given [here](https://community.letsencrypt.org/t/solution-client-with-the-currently-selected-authenticator-does-not-support-any-combination-of-challenges-that-will-satisfy-the-ca/49983) and if you’re serving files for that domain out of a directory on that server, you can run the following command:

```
sudo certbot --authenticator webroot --webroot-path <path to served directory> --installer nginx -d <domain>
```

If you’re not serving files out of a directory on the server, you can temporarily stop your server while you obtain the certificate and restart it after Certbot has obtained the certificate. This would look like:

```
sudo certbot --authenticator standalone --installer nginx -d <domain> --pre-hook "service nginx stop" --post-hook "service nginx start"
```

e.g.

1. Create your virtual server conf - the given config below routes an node/express app running on localhost:7777 with a public directory in /opt/mysite-build/app :

```
server {
       listen         80;
       listen    [::]:80;
       server_name    my.domain.com;
       return         301 https://$server_name$request_uri;
}

upstream app_test {
	# point to the running node
	server 127.0.0.1:7777;
}

server {
	listen 443 ssl http2;
	listen [::]:443 ssl http2;
	server_name my.domain.com;
	
	# set the default public directory for your node
	root /opt/mysite-build/app;
	
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
		proxy_pass http://wiki2_test;
    	proxy_redirect off;
    	proxy_read_timeout 240s;
	}
	
	# use NGINX to cache static resources that are requested regularly
	location ~* \.(css|js|jpg|png|ico)$ {
		expires 168h;
	}

}
```

Test your your site by opening my.domain.com inside your browser - you should be automatically redirected to https://my.domain.com and be given a certificate warning. Click to proceed anyway to access your site.

Now run:

```
sudo certbot --authenticator webroot --webroot-path /opt/mysite-build/app --installer nginx -d my.domain.com
```

certbot will modify your NGINX config automatically!


## 9 Search Engine Setup and Configuration

### Installing Elasticsearch 6.x on CentOS

Elasticsearch is a distributed, JSON-based search and analytics engine designed for horizontal scalability, maximum reliability, and easy management.

#### Import the Elasticsearch PGP Key

```
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
```

### Installing from the RPM repository

Create a file called elasticsearch.repo in the _/etc/yum.repos.d/_ directory and add the following lines:

```
[elasticsearch-6.x]
name=Elasticsearch repository for 6.x packages
baseurl=https://artifacts.elastic.co/packages/6.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
```

And your repository is ready for use. You can now install Elasticsearch with one of the following commands:

```
sudo yum install elasticsearch
```

#### Running Elasticsearch with _systemd_

To configure Elasticsearch to start automatically when the system boots up, run the following commands:

```
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable elasticsearch.service
```

Apparently there is no way to quietly reload the Elasticsearch service after changing the config file - you will be required to stop and restart instead:

```
sudo systemctl stop elasticsearch.service
sudo systemctl start elasticsearch.service
```

These commands provide no feedback as to whether Elasticsearch was started successfully or not. Instead, this information will be written in the log files located in /var/log/elasticsearch/.

#### Checking that Elasticsearch is running

You can test that your Elasticsearch node is running by sending an HTTP request to port 9200 on localhost:

```
curl -XGET 'localhost:9200/?pretty'
```

```
http://localhost:9200/_cat/indices?v&pretty
```

#### Configuring Elasticsearch

Elasticsearch loads its configuration from the _/etc/elasticsearch/elasticsearch.yml_ file by default. Examples:

* __cluster.name:__ e.g. _instar-wiki_
* __node.name__ e.g. _c21_
* __node.attr.rack:__ e.g _r44_
* __path.data:__ _/path/to/data_
* __path.logs:__ _/path/to/logs_
* __network.host:__ _localhost_ [see config](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html#network-interface-values) __*__
* __http.port:__ _9200_
* __http.cors:__ _enabled:_ true , _allow-origin:_ /https?:\/\/localhost(:[0-9]+)?/, _allow-origin:_ /https?:\/\/localhost(:[0-9][0-9][0-9][0-9])?/
* __*__ _e.g. network.host: 127.0.0.1, 192.168.1.200, 7.114.21.49_


The RPM places config files, logs, and the data directory in the appropriate locations for an RPM-based system:

| Type | Description | Default Location | Setting |
|---|---|---|---|
| home | Elasticsearch home directory or $ES_HOME | _/usr/share/elasticsearch_ |  |
| bin | Binary scripts including elasticsearch to start a node and elasticsearch-plugin to install plugins | _/usr/share/elasticsearch/bin_ |   |
| conf | Configuration files including elasticsearch.yml | _/etc/elasticsearch_ | ES_PATH_CONF |
| conf | Environment variables including heap size, file descriptors. | _/etc/sysconfig/elasticsearch_ |   |
| data | The location of the data files of each index / shard allocated on the node. Can hold multiple locations. | _/var/lib/elasticsearch_ | path.data |
| logs | Log files location. | _/var/log/elasticsearch_ | path.logs |
| plugins | Plugin files location. Each plugin will be contained in a subdirectory. | _/usr/share/elasticsearch/plugins_ |   |


### Installing Kibana 6.x on CentOS

Kibana gives shape to your data and is the extensible user interface for configuring and managing all aspects of the Elastic Stack.

Create a file called kibana.repo in the _/etc/yum.repos.d/_ directory and add the following lines:

```
[kibana-6.x]
name=Kibana repository for 6.x packages
baseurl=https://artifacts.elastic.co/packages/6.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
```

And your repository is ready for use. You can now install Kibana with one of the following command:

```
sudo yum install kibana
```


#### Running Kibana with _systemd_

To configure Kibana to start automatically when the system boots up, run the following commands:

```
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable kibana.service
```

Kibana can be started and stopped as follows:

```
sudo systemctl stop kibana.service
sudo systemctl start kibana.service
```

These commands provide no feedback as to whether Kibana was started successfully or not. Instead, this information will be written in the log files located in _/var/log/kibana/_. Kibana loads its configuration from the _/etc/kibana/kibana.yml_ file by default. Examples:


* __elasticsearch.url:__ Default: _http://localhost:9200_ The URL of the Elasticsearch instance to use for all your queries.
* __server.port:__ Server port for the Kibana web UI - _default 5601_
* __server.host:__ Specifies the address to which the Kibana server will bind. IP addresses and host names are both valid values. The default is _localhost_, which usually means remote machines will not be able to connect. To allow connections from remote users, set this parameter to a non-loopback address.
* __console.enabled:__  Default: true Set to false to disable Console.
* __elasticsearch.username:__ s. below
* __elasticsearch.password:__ If your Elasticsearch is protected with basic authentication, these settings provide the username and password that the Kibana server uses to perform maintenance on the Kibana index at startup. Your Kibana users still need to authenticate with Elasticsearch, which is proxied through the Kibana server. (see X-Pack below)
* __server.ssl.enabled:__ Default: "false" Enables SSL for outgoing requests from the Kibana server to the browser. When set to true, server.ssl.certificate and server.ssl.key are required
* __server.ssl.certificate:__ s. below
* __server.ssl.key:__ Paths to the PEM-format SSL certificate and SSL key files, respectively.
* __server.ssl.certificateAuthorities:__ List of paths to PEM encoded certificate files that should be trusted.
* __server.ssl.cipherSuites:__ Default: _ECDHE-RSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-AES256-GCM-SHA384, DHE-RSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-SHA256, DHE-RSA-AES128-SHA256, ECDHE-RSA-AES256-SHA384, DHE-RSA-AES256-SHA384, ECDHE-RSA-AES256-SHA256, DHE-RSA-AES256-SHA256, HIGH,!aNULL, !eNULL, !EXPORT, !DES, !RC4, !MD5, !PSK, !SRP, !CAMELLIA_. Details on the format, and the valid options, are available via the [OpenSSL cipher list format documentation](https://www.openssl.org/docs/man1.0.2/apps/ciphers.html#CIPHER-LIST-FORMAT)
* __server.ssl.keyPassphrase:__ The passphrase that will be used to decrypt the private key. This value is optional as the key may not be encrypted.
* __server.ssl.redirectHttpFromPort:__ Kibana will bind to this port and redirect all http requests to https over the port configured as server.port.
* __server.ssl.supportedProtocols:__ _Default_: TLSv1, TLSv1.1, TLSv1.2 Supported protocols with versions. Valid protocols: TLSv1, TLSv1.1, TLSv1.2
* __status.allowAnonymous:__ Default: false If authentication is enabled, setting this to true allows unauthenticated users to access the Kibana server status API and status page.



| Type | Description | Default Location | Setting |
|---|---|---|---|
| home | Kibana home directory or $KIBANA_HOME | _/usr/share/kibana_ |  |
| bin | Binary scripts including kibana to start the Kibana server and kibana-plugin to install plugins | _/usr/share/kibana/bin_ |   |
| config | Configuration files including kibana.yml | _/etc/kibana_ | |
| data | The location of the data files written to disk by Kibana and its plugins | _/var/lib/kibana_ | path.data |
| optimize | Transpiled source code. Certain administrative actions (e.g. plugin install) result in the source code being retranspiled on the fly. | _/usr/share/kibana/optimize_ | |
| plugins | Plugin files location. Each plugin will be contained in a subdirectory. | _/usr/share/kibana/plugins_ |   |


### Install X-Pack

X-Pack is a single extension that integrates handy features — security, alerting, monitoring, reporting, graph exploration, and machine learning — you can trust across the Elastic Stack.

#### Elasticsearch Security

We need to add a user athentication to our Elasticsearch / Kibana setup. We will do this by installing X-Pack. To get started with installing the Elasticsearch plugin, go to _/etc/elasticsearch/_ and call the following function:

```
bin/elasticsearch-plugin install x-pack
```

Now restart Elasticsearch:

```
sudo systemctl stop elasticsearch.service
sudo systemctl start elasticsearch.service
```

You can either use the auto function to generate user passwords for Elasticsearch, Kibana (and the not yet installed Logstash):

```
bin/x-pack/setup-passwords auto
```

or swap the _auto_ flag with _interactive_ to use your own user logins. The auto output will look something like this:

```
Changed password for user kibana 
PASSWORD kibana = *&$*(80gfddzg

Changed password for user logstash_system
PASSWORD logstash_system = 58#$)Qljfksh

Changed password for user elastic
PASSWORD elastic = jgfisg)#*%&(@*#)
```

__Now every interaction with Elasticsearch or Kibana will require you to authenticate with _username: elastic_ and _password: jgfisg)#*%&(@*#)___


#### Kibana Security

Now we repeat these steps with Kibana. First navigate to _/etc/kibana/_ and call the following function:

```
bin/kibana-plugin install x-pack
```

And we have to add the login that Kibana has to use to access Elasticsearch (auto generated above) to the _kibana.yml_ file in _/etc/kibana/_:

```
elasticsearch.username: "kibana"
elasticsearch.password:  "*&$*(80gfddzg"
```

Now restart Kibana:

```
sudo systemctl stop kibana.service
sudo systemctl start kibana.service
```

Now navigate your browser _http://localhost:5601/_ and login with the "elastic" user we generated above.


### Enabling Anonymous Access

Incoming requests are considered to be anonymous if no authentication token can be extracted from the incoming request. By default, anonymous requests are rejected and an authentication error is returned (status code 401). To allow anonymous user to send search queries (Read access to specified indices), we need to add the following lines to the _elasticsearch.yml_ file in _/etc/elasticsearch/_:

```
xpack.security.authc:
  anonymous:
    username: anonymous_user 
    roles: wiki_reader 
    authz_exception: true 
```

Now we have to switch to the Kibana webUI on _http://localhost:5601/_ and create the _role:_ *wiki_reader* to allow read access to the wiki indices. First switch to the __Management__ tab and click on user:

![Add a Elasticsearch User with Read Access](./kibana_01.png)


Then click on __Add a User__ and add a user with the __watcher_user__ role:

![Add a Elasticsearch User with Read Access](./kibana_02.png)


Switch back to the __Management__ tab and click on role:

![Add a Elasticsearch User with Read Access](./kibana_03.png)


Click on __Create Role__ and add the name **wiki_reader** that we choose for the role of the anonymous user inside the elasticsearch.yml file, assign the **monitor_watcher** privilege and choose the indices that you want the anonymous user to have __READ__ access to:

![Add a Elasticsearch User with Read Access](./kibana_04.png)


Your configuration will be active after restarting Elasticsearch. Now you can use webservices to read from your ES database. But only the __elastic__ user has the privileg to __WRITE__ and to work in Kibana.


https://github.com/elastic/cookbook-elasticsearch/tree/4.0.0-beta

https://github.com/elastic/ansible-elasticsearch

https://www.elastic.co/blog/deploying-elasticsearch-200-with-chef



