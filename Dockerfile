# Multi-stage build for Azure Container App deployment

# Build frontend
FROM node:26-alpine AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ .
RUN npm run build

# Final image with backend serving frontend
FROM python:3.14-slim

WORKDIR /app

# Install backend dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/app/ ./app/

# Copy built frontend
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Create data directory for SQLite (inside app dir for local storage)
RUN mkdir -p /app/data

ENV DATABASE_URL=sqlite:////app/data/bibmap.db
ENV PORT=8000

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
