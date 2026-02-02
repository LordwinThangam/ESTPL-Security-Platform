#!/bin/bash

# 🔍 GitHub Repository Verification Script
# This script checks if all required files are in your repository

echo "=========================================="
echo "🔍 ESTPL GitHub Repository Checker"
echo "=========================================="
echo ""

read -p "Enter your GitHub repository URL (e.g., https://github.com/username/repo): " REPO_URL

if [ -z "$REPO_URL" ]; then
    echo "❌ No repository URL provided. Exiting."
    exit 1
fi

# Extract owner and repo name from URL
REPO_PATH=$(echo "$REPO_URL" | sed 's|https://github.com/||' | sed 's|.git||')

echo ""
echo "Checking repository: $REPO_PATH"
echo ""

# List of required files
declare -a required_files=(
    "app_enhanced.py"
    "siem_engine.py"
    "estpl_enhanced.db"
    "requirements.txt"
    "Procfile"
    "runtime.txt"
    "render.yaml"
    ".gitignore"
)

echo "📋 Checking required files..."
echo ""

# Check each file using GitHub API
for file in "${required_files[@]}"
do
    echo -n "Checking $file... "
    
    # Use GitHub API to check if file exists
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://api.github.com/repos/$REPO_PATH/contents/$file")
    
    if [ "$STATUS" == "200" ]; then
        # Get file size
        SIZE=$(curl -s "https://api.github.com/repos/$REPO_PATH/contents/$file" | grep -o '"size": [0-9]*' | grep -o '[0-9]*')
        SIZE_KB=$((SIZE / 1024))
        echo "✅ Found ($SIZE_KB KB)"
    else
        echo "❌ NOT FOUND"
    fi
done

echo ""
echo "📁 Checking templates directory..."
TEMPLATES_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://api.github.com/repos/$REPO_PATH/contents/templates")

if [ "$TEMPLATES_STATUS" == "200" ]; then
    TEMPLATE_COUNT=$(curl -s "https://api.github.com/repos/$REPO_PATH/contents/templates" | grep -o '"name":' | wc -l)
    echo "✅ templates/ directory exists with $TEMPLATE_COUNT files"
else
    echo "❌ templates/ directory NOT FOUND"
fi

echo ""
echo "📝 Checking Procfile content..."
PROCFILE_CONTENT=$(curl -s "https://api.github.com/repos/$REPO_PATH/contents/Procfile" | grep -o '"content": "[^"]*"' | cut -d'"' -f4 | base64 -d 2>/dev/null)

if [ ! -z "$PROCFILE_CONTENT" ]; then
    echo "Content: $PROCFILE_CONTENT"
    
    if [[ "$PROCFILE_CONTENT" == *"app_enhanced:app"* ]]; then
        echo "✅ Procfile correctly references app_enhanced:app"
    else
        echo "⚠️  WARNING: Procfile may have incorrect content"
    fi
else
    echo "❌ Could not read Procfile content"
fi

echo ""
echo "=========================================="
echo "📊 Summary"
echo "=========================================="
echo ""
echo "Repository: https://github.com/$REPO_PATH"
echo ""
echo "If files are missing:"
echo "1. cd to your local estpl-full-deployment directory"
echo "2. Run: git add -A"
echo "3. Run: git commit -m 'Add all files'"
echo "4. Run: git push origin main"
echo ""
echo "Then:"
echo "1. Delete your Render service"
echo "2. Create a NEW Render service"
echo "3. Connect the same GitHub repo"
echo ""
