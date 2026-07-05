# NetworkMaster Restore Guide v1.2.0

This guide explains how to restore NetworkMaster after a server failure.

## Production routes

Homepage: https://networkmaster.org/
DNS Checker: https://networkmaster.org/tools/dns-checker/
Persian DNS Checker: https://networkmaster.org/tools/dns-checker/fa/

## Important paths

Application: /root/dns-checker-app
Homepage source in repository: networkmaster-main/
Homepage production path: /var/www/networkmaster-main
Custom error pages in repository: recovery/error-pages/
Custom error pages production path: /var/www/networkmaster-errors
Nginx config backup: recovery/nginx/networkmaster.org.conf

## Restore steps

1. Clone repository

cd /root
git clone https://github.com/musictestt/dns-checker-app.git dns-checker-app
cd /root/dns-checker-app
npm install --omit=dev

2. Restore homepage files

mkdir -p /var/www/networkmaster-main
cp -r /root/dns-checker-app/networkmaster-main/* /var/www/networkmaster-main/

3. Restore custom error pages

mkdir -p /var/www/networkmaster-errors
cp -r /root/dns-checker-app/recovery/error-pages/* /var/www/networkmaster-errors/

4. Restore Nginx config

cp /root/dns-checker-app/recovery/nginx/networkmaster.org.conf /etc/nginx/sites-available/networkmaster.org
ln -sf /etc/nginx/sites-available/networkmaster.org /etc/nginx/sites-enabled/networkmaster.org
nginx -t
systemctl reload nginx

5. Restore SSL certificate

Do not store SSL private keys in GitHub.
Restore SSL files from private backup or reissue the certificate.
Expected SSL paths:
/etc/nginx/ssl/networkmaster.org/fullchain.crt
/etc/nginx/ssl/networkmaster.org/Private.key

6. Start backend with PM2

If the process does not exist:
cd /root/dns-checker-app
pm2 start server.js --name dns-checker-backend
pm2 save

If the process already exists:
pm2 restart dns-checker-backend
pm2 save

7. Test

curl -I https://networkmaster.org/
curl -I https://networkmaster.org/tools/dns-checker/
curl -I https://networkmaster.org/tools/dns-checker/fa/

Expected result: HTTP/2 200

## Security notes

Never commit these files to GitHub:
- SSL private keys
- .env
- passwords
- tokens
- private backup archives
- PM2 dumps containing secrets
