#!/usr/bin/env bash
# Exit immediately if a command exits with a non-zero status
set -o errexit

echo "==> Building Next.js Frontend Static Export..."
cd frontend
npm install
npm run build
cd ..

echo "==> Installing FastAPI Backend Dependencies..."
cd backend
pip install -r requirements.txt
cd ..

echo "==> Build Process Complete!"
