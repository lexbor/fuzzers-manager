# Deployment Guide for Ubuntu Server

This guide describes how to deploy the Node.js Fuzzer Management System on an Ubuntu server using Nginx as a reverse proxy and PM2 for process management.

## 1. Prerequisites

Update your system and install necessary packages:

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y nginx git curl build-essential
```

## 2. Install Node.js

Install Node.js (LTS version recommended) using NodeSource:

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
```

Verify installation:
```bash
node -v
npm -v
```

## 3. Setup the Project

1.  **Copy your project files** to the server (e.g., via `git clone` or `scp`). Let's assume we put it in `/var/www/fuzzer-manager`.

    ```bash
    sudo mkdir -p /var/www/fuzzer-manager
    # (Upload your files here)
    cd /var/www/fuzzer-manager
    ```

2.  **Install Dependencies**:

    ```bash
    npm install
    ```

3.  **Fix Permissions**:
    The application needs to write to `fuzzers.json` and create directories for logs/crashes. Ensure the user running the app has permissions.

    ```bash
    # If running as current user (recommended for simplicity)
    sudo chown -R $USER:$USER /var/www/fuzzer-manager
    ```

## 4. Setup PM2 (Process Manager)

PM2 keeps your Node.js application running in the background and restarts it if it crashes.

1.  **Install PM2**:

    ```bash
    sudo npm install -g pm2
    ```

2.  **Start the Application**:

    ```bash
    pm2 start server.js --name "fuzzer-app"
    ```

3.  **Setup Startup Script** (so it starts on boot):

    ```bash
    pm2 startup
    # Run the command displayed by the output of the above command
    pm2 save
    ```

## 5. Configure Nginx

Configure Nginx to proxy requests to your Node.js app running on port 3000.

1.  **Create a new configuration file**:

    ```bash
    sudo nano /etc/nginx/sites-available/fuzzer-manager
    ```

2.  **Add the following content** (replace `your_domain_or_ip` with your actual domain or server IP):

    ```nginx
    server {
        listen 80;
        server_name your_domain_or_ip;

        location / {
            proxy_pass http://localhost:3000;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
            
            # Forward real IP
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
    ```

3.  **Enable the site**:

    ```bash
    sudo ln -s /etc/nginx/sites-available/fuzzer-manager /etc/nginx/sites-enabled/
    ```

4.  **Test and Restart Nginx**:

    ```bash
    sudo nginx -t
    sudo systemctl restart nginx
    ```

## 7. Maintenance

-   **View Logs**: `pm2 logs fuzzer-app`
-   **Restart App**: `pm2 restart fuzzer-app`
-   **Update App**: Pull new code, `npm install`, then `pm2 restart fuzzer-app`.
