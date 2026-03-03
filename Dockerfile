FROM node:20-slim

# Instalace závislostí pro Debian (Slim verze)
# Potřebujeme je, aby se mohl správně zkompilovat modul better-sqlite3
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && npm set progress=false

WORKDIR /app

# Kopírování package souborů a instalace
COPY package.json package-lock.json* ./
RUN npm install --production

# Kopírování zbytku zdrojového kódu
COPY . .

# Ujištění, že složky pro data a upload existují
RUN mkdir -p /app/data/uploads

EXPOSE 3000

# Spuštění aplikace
CMD ["node", "server.js"]
