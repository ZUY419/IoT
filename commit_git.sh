PASSWORD="todoroki"
branch="main"

echo -e "=== Remove .git"
echo "$PASSWORD" | sudo -S rm -rf .git

echo -e "\n=== Initialization .git"
git init

echo -e "\n=== Switch/Create ${branch} branch"
git checkout -b ${branch}

echo -e "\n=== Add data to .git"
git add .   # 若要加入全部檔案，請改為 git add .

echo -e "\n=== Commit comment"
git commit -m "test"

echo -e "\n=== Add origin"
git remote add origin https://github.com/ZUY419/IoT

echo -e "\n=== Push to GitHub"
git push -u origin ${branch} --force
