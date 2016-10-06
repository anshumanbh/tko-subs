# tkogit
Takeover Domains that have dangling CNAMES pointing to Github Pages

![Demo](/imgs/out.gif)

go get github.com/anshumanbh/go-github/github
go get golang.org/x/oauth2
go get github.com/subosito/gotenv

add token to sample-env and rename it to .env 

go run /path/to/tokgit.go /path/to/subdomains.txt
