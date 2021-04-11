# Let's Encrypt guide
source: https://github.com/wmnnd/nginx-certbot

## Setup
Nginx will not start without a cert, therefore we create a self-signed cert until we get a let's encrypt cert.
```
$ ./init-letsencrypt.sh
$ docker-compose up
```

# Nginx simple conf
```
server {
        listen 80;
        listen [::]:80;

        root /var/www/html;
        index index.html index.htm index.nginx-debian.html;

        server_name introspect.no www.introspect.no;

        location / {
                proxy_pass http://introspect-frontend:80;
        }

        location ~ /.well-known/acme-challenge {
                allow all;
                root /var/www/html;
        }
}
```

# Nginx prod conf
```
server {
        listen 80;
        listen [::]:80;
        server_name introspect.no www.introspect.no;


        location ~ /.well-known/acme-challenge {
          allow all;
          root /var/www/html;
        }

        location / {
                rewrite ^ https://$host$request_uri? permanent;
        }
}

server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name introspect.no www.introspect.no;

        server_tokens off;

        ssl_certificate /etc/letsencrypt/live/introspect.no/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/introspect.no/privkey.pem;

        ssl_buffer_size 8k;

        ssl_dhparam /etc/ssl/certs/dhparam-2048.pem;

        ssl_protocols TLSv1.2 TLSv1.1 TLSv1;
        ssl_prefer_server_ciphers on;

        ssl_ciphers ECDH+AESGCM:ECDH+AES256:ECDH+AES128:DH+3DES:!ADH:!AECDH:!MD5;

        ssl_ecdh_curve secp384r1;
        ssl_session_tickets off;

        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 8.8.8.8;

        location / {
                try_files $uri @introspect-frontend;
        }

        location @introspect-frontend {
                proxy_pass http://introspect-frontend:80;
                add_header X-Frame-Options "SAMEORIGIN" always;
                add_header X-XSS-Protection "1; mode=block" always;
                add_header X-Content-Type-Options "nosniff" always;
                add_header Referrer-Policy "no-referrer-when-downgrade" always;
                add_header Content-Security-Policy "default-src * data: 'unsafe-eval' 'unsafe-inline'" always;
                # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
                # enable strict transport security only if you understand the implications
        }

        root /var/www/html;
        index index.html index.htm index.nginx-debian.html;
}
```