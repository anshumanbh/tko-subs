# tko-subs

This tool allows taking over Domains/Subdomains that have dangling CNAMES pointing to:

* Github Pages
* Heroku Apps

This tool will also tell you potential takeovers for certain CMS websites for which automation has not yet been implemented. This is primarily because there are no readily available GO clients for those websites or they haven't exposed their API to be able to automate domain takeovers. They are:

* Unbounce 
* Tumblr
* Shopify 

PS - This project is a work in progress. I will be adding more CMS websites, also will try to automate takeover as much as I can. 


### Disclaimer: DONT BE A JERK! 

Needless to mention, please use this tool very very carefully. Run it only if you know what you are doing and you are sure you want to take over a domain. I won't be responsible for any consequences. 


### Watch the demo here

[![DEMO](https://i.ytimg.com/vi/5i6Vx9f6hIc/2.jpg)](https://youtu.be/5i6Vx9f6hIc)


### Pre-requisites

We need GO installed. Once you have GO, `go get` the following libraries:
* go get github.com/anshumanbh/go-github/github
* go get golang.org/x/oauth2
* go get github.com/subosito/gotenv
* go get github.com/bgentry/heroku-go

The next thing we need to do is to add the following values to the `.env` file:
* Github's Personal Access Token - Make sure this token has the rights to create repositories, references, contents, etc. You can create this token here - https://github.com/settings/tokens
* Heroku Username and API key
* Heroku app name - You can create a static app on Heroku with whatever you want to be displayed on its homepage by following the instructions here - https://gist.github.com/wh1tney/2ad13aa5fbdd83f6a489. Once you create that app, just copy paste that app name in the .env file. We will use that app to takeover the domain (with the dangling CNAME to another Heroku app). 

Just add the above values to sample-env provided with this repo and rename it to .env and you should be good to go!


### How to run?

Once you have everything installed, it is as simple as issuing the command:
`go run /path/to/toksubs.go /path/to/subdomains.txt`


### What is going on under the hood?

This will iterate over all the domains in the `subdomains.txt` file and:
* See if they are reachable. If not, it times out and proceeds to the next domain
* If they are reachable, it matches the regular expression for dangling Github Pages, Heroku apps, etc. 
* If it doesn't match, it says `Not found`
* If the regular expression matches, it tries to takeover the domain based on what's needed to takeover the domains in that website. For example, to takeover a Github Page, the code will:
	* Create a repo
	* Create a branch `gh-pages` in that repo
	* Upload `CNAME` and `index.html` to the `gh-pages` branch in that repo. Here, `CNAME` contains the domain that needs to be taken over. `index.html` contains the text `This domain is temporarily suspended` that is to be displayed once the domain is taken over. 
* Similarly, for Heroku apps, the code will:
	* Add the dangling domain to your Heroku app (whose name you will be providing in the .env file)
* And, that's it! 


### Future Work

* Take CMS name and regex from user or .env file and then automatically hook them into the tool to be able to find it


### Credits

Thanks to Luke Young (@TheBoredEng) for helping me out with the go-github library.
Thanks to Frans Rosen (@fransrosen) for helping me understand the technical details that are required for some of the takeovers.