#!/bin/bash

# 🚀 Quick Deploy Script for ESTPL Enhanced Security Platform
# This script will help you push your fixed app to GitHub

echo "=========================================="
echo "🚀 ESTPL Quick Deploy to GitHub & Render"
echo "=========================================="
echo ""

# Check if we're in the right directory
if [ ! -f "app_enhanced.py" ]; then
    echo "❌ Error: app_enhanced.py not found!"
    echo "Please run this script from the estpl-full-deployment directory"
    exit 1
fi

echo "✅ Found app_enhanced.py"
echo ""

# Initialize git if not already done
if [ ! -d ".git" ]; then
    echo "📝 Initializing Git repository..."
    git init
    echo "✅ Git initialized"
else
    echo "✅ Git already initialized"
fi

echo ""
echo "================================================"
echo "⚠️  IMPORTANT: Set Your GitHub Repository URL"
echo "================================================"
echo ""
echo "1. Go to https://github.com/new"
echo "2. Create a new repository (e.g., 'estpl-security-platform')"
echo "3. Copy the repository URL"
echo ""
read -p "Enter your GitHub repository URL (e.g., https://github.com/username/repo.git): " REPO_URL

if [ -z "$REPO_URL" ]; then
    echo "❌ No repository URL provided. Exiting."
    exit 1
fi

echo ""
echo "📦 Adding files to Git..."
git add .
echo "✅ Files added"

echo ""
echo "💾 Creating commit..."
git commit -m "ESTPL Enhanced Security Platform - FIXED version ready for production"
echo "✅ Commit created"

echo ""
echo "🔗 Setting remote origin..."
git remote remove origin 2>/dev/null
git remote add origin "$REPO_URL"
echo "✅ Remote set to: $REPO_URL"

echo ""
echo "🚀 Pushing to GitHub..."
git branch -M main
git push -u origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "=========================================="
    echo "✅ SUCCESS! Code pushed to GitHub!"
    echo "=========================================="
    echo ""
    echo "📋 NEXT STEPS:"
    echo ""
    echo "1. Go to https://render.com"
    echo "2. Click 'New +' → 'Web Service'"
    echo "3. Connect your GitHub repository"
    echo "4. Render will auto-detect settings from render.yaml"
    echo "5. Click 'Create Web Service'"
    echo "6. Wait ~2 minutes for deployment"
    echo "7. Your app will be live! 🎉"
    echo ""
    echo "Expected URL: https://estpl-security-platform.onrender.com"
    echo "Default login: admin / admin123"
    echo ""
else
    echo ""
    echo "❌ Push failed. Common issues:"
    echo "1. Repository doesn't exist - create it first on GitHub"
    echo "2. Authentication error - make sure you're logged in to Git"
    echo "3. Repository URL is incorrect"
    echo ""
    echo "Try these commands manually:"
    echo "  git remote -v  # Check remote URL"
    echo "  git push -u origin main  # Try pushing again"
fi
