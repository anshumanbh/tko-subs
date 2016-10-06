# tkogit

Takeover Domains that have dangling CNAMES pointing to Github Pages. 


### Disclaimer: DONT BE A JERK! 

Needless to mention, please use this tool very very carefully. Run it only if you know what you are doing and you are sure you want to take over a domain. I won't be responsible for any consequences. 


### Demo

![Demo](/imgs/in2.gif)


### Pre-requisites

We need GO installed. Once you have GO, `go get` the following libraries:
* go get github.com/anshumanbh/go-github/github
* go get golang.org/x/oauth2
* go get github.com/subosito/gotenv

The next thing we need to do is to add your Github's Personal Access Token to a `.env` file.
Just add the token to sample-env provided with this repo and rename it to .env
PS - Make sure the token has the rights to create repositories, references, contents, etc.  


### How to run?

Once you have everything installed, it is as simple as issuing the command:
`go run /path/to/tokgit.go /path/to/subdomains.txt`


### What is going on under the hood?

This will iterate over all the domains in the `subdomains.txt` file and:
* See if they are reachable. If not, it times out and proceeds to the next domain
* If they are reachable, it matches the regular expression for dangling Github Pages
* If it doesn't match, it says `Not found`
* If the regular expression matches, it tries to:
	* Create a repo
	* Create a branch in that repo
	* Upload `CNAME` and `index.html` to that branch in that repo. `CNAME` contains the domain that needs to be taken over. `index.html` contains the text `This domain is temporarily suspended` that is displayed once the domain is taken over. 
* And, that's it! 


### Future Work

I am planning to make this more generalized by including different usecases like Heroku, S3, Shopify, etc. 
