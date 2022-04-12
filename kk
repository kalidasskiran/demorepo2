MONGO_URI="mongodb://admin:password@localhost:27017/test?authSource=admin" go run main.go

git init
git remote add origin https://github.com/kalidasskiran/demorepo2.git
git add .
git commit -m "initial commit"
git push origin master
go mod vendor


docker run -d -v $PWD/conf:/usr/local/etc/redis --name redis -p 6379:6379 redis:6.0
JWT_SECRET=eUbP9shywUygMx7u MONGO_URI="mongodb://admin:password@localhost:27017/test?authSource=admin" MONGO_DATABASE=demo go run *.go
