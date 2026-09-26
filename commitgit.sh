echo -e "=== Remove .git"
sudo rm -rf .git

echo -e "\n=== Initialization .git"
git init

echo -e "\n=== Add all data to .git"
git add .

echo -e "\n=== Commit comment"
git commit -m "test"

echo -e "\n=== Add origin"
git remote add origin https://github.com/ZUY419/IoT

echo -e "\n=== Turn branch to main"
git checkout -b main

echo -e "\n=== Push to GitHub"
git push -u origin main --force
