FROM node:18-alpine

# install build dependencies for better-sqlite3
RUN apk add --no-cache python3 make g++ \
    && npm set progress=false

WORKDIR /app

# copy package files and install
COPY package.json package-lock.json* ./
RUN npm install --production

# copy rest of source
COPY . .

# ensure data directory exists
RUN mkdir -p /app/data/uploads

EXPOSE 3000
CMD ["node", "server.js"]
