FROM node:20-alpine

# Instalace závislostí pro SQLite na Alpine
RUN apk add --no-cache python3 make g++ sqlite-dev

WORKDIR /app

# Kopírování a instalace
COPY package*.json ./
RUN npm install --production

COPY . .

# Práva pro zápis do databáze (tohle může být ten problém!)
RUN mkdir -p /app/data/uploads && chmod -R 777 /app/data

EXPOSE 3000

# Spuštění s explicitním výpisem chyb
CMD ["node", "server.js"]
