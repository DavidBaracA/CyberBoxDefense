FROM node:20-alpine

WORKDIR /workspace/apps/frontend

COPY apps/frontend/package.json /workspace/apps/frontend/package.json
COPY apps/frontend/vite.config.js /workspace/apps/frontend/vite.config.js
COPY apps/frontend/index.html /workspace/apps/frontend/index.html
COPY apps/frontend/src /workspace/apps/frontend/src

RUN npm install

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
