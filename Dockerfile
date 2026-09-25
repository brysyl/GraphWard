# Step 1: Build Next.js Frontend Static Export
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# Step 2: Set up Python FastAPI Backend & serve Frontend static files
FROM python:3.11-slim
WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ ./backend

# Copy Next.js exported 'out' folder into place
COPY --from=frontend-builder /app/frontend/out /app/frontend/out

# Expose Render dynamic port
ENV PORT=10000
EXPOSE 10000

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
