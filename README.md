# tko-subs

This tool allows:
* To check whether a subdomain has a dangling CNAME pointing to a CMS provider (Heroku, Github, Shopify, Amazon S3, Amazon CloudFront, etc.) that can be taken over.

* To actually take over those subdomain by providing a flag `-takeover`. Currently, take over is only supported for Github Pages and Heroku Apps and by default the take over functionality is off.

* To specify your own CMS providers and check for them via the [providers-data.csv](providers-data.csv) file. In that file, you would mention the CMS name, their CNAME value, their string that you want to look for and whether it only works over HTTP or not. Check it out for some examples.


### Disclaimer: DONT BE A JERK!

Needless to mention, please use this tool very very carefully. The authors won't be responsible for any consequences.
By default, this tool does not allow taking over of subdomains. If you want to do it, just specify the `-takeover` flag.


### Pre-requisites

We need GO installed. Once you have GO, `go get` the following libraries:
* go get github.com/gocarina/gocsv
* go get golang.org/x/oauth2
* go get github.com/subosito/gotenv
* go get github.com/bgentry/heroku-go
* go get github.com/google/go-github/github

The next thing we need to do is to add the following values to the `.env` file:
* Github's Personal Access Token - Make sure this token has the rights to create repositories, references, contents, etc. You can create this token here - https://github.com/settings/tokens
* Heroku Username and API key
* Heroku app name - You can create a static app on Heroku with whatever you want to be displayed on its homepage by following the instructions here - https://gist.github.com/wh1tney/2ad13aa5fbdd83f6a489. Once you create that app, just copy paste that app name in the .env file. We will use that app to takeover the domain (with the dangling CNAME to another Heroku app).

Just add the above values to sample-env provided with this repo and rename it to .env and you should be good to go!
NOTE - You only need these values if you want to take over subdomains. By default, that's not required.


### How to run?

Once you have everything installed, it is as simple as issuing the command:
`go run /path/to/toksubs.go -domains=domains.txt -data=providers-data.csv -output=output.csv`

If you want to take over as well, the command would be:
`go run /path/to/toksubs.go -domains=domains.txt -data=providers-data.csv -output=output.csv -takeover`

By default:
* the `domains` flag is set to `domains.txt`
* the `data` flag is set to `providers-data.csv`
* the `output` flag is set to `output.csv`
* the `takeover` flag is not set so no take over by default

So, simply running `go run /path/to/toksubs.go` would run with the default values mentioned above.


### How is providers-data.csv formatted?

name,cname,error,http

* name: The name of the provider (e.g. github)
* cname: The CNAME used to map a website to the provider's content (e.g. github.io)
* error: The error message returned for an unclaimed subdomain (e.g. "There isn't a GitHub Pages site here")
* http: Whether to use http (not https, which is the default) to connect to the site (true/false)


### How is the output formatted?

Domain,Provider,IsVulnerable,IsTakenOver,RespString

* Domain: The domain checked
* Provider: The provider the domain was found to be using
* IsVulnerable: Whether the domain was found to be vulnerable or not (true/false)
* IsTakenOver: Whether the domain was taken over or not (true/false)
* RespString: The message that the subdomain was checked against


### What is going on under the hood?

This will iterate over all the domains (concurrently using GoRoutines) in the `subdomains.txt` file and:
* See if they have dangling CNAME records aka dead DNS records by using `dig`.
* If they have dead DNS records, it tries to curl them and get back a response and then try to see if that response matches any of the data provider strings mentioned in the [providers-data.csv](providers-data.csv) file.
	* For some cases like Heroku apps, if it has a dead DNS record and can't curl it, it will assume its vulnerable. Heroku does not respond back with anything if the subdomains are removed from user accounts so curl'ing it doesn't fetch anything (unlike other CMS providers) but the dead record still exists and can be taken over so we want to know about them.
* If the response matches, we mark that domain as vulnerable.
* Next, depending upon whether the `takeover` flag is mentioned or not, it will try to take over that vulnerable subdomain.
* For example, to takeover a Github Page, the code will:
	* Create a repo
	* Create a branch `gh-pages` in that repo
	* Upload `CNAME` and `index.html` to the `gh-pages` branch in that repo. Here, `CNAME` contains the domain that needs to be taken over. `index.html` contains the text `This domain is temporarily suspended` that is to be displayed once the domain is taken over.
* Similarly, for Heroku apps, the code will:
	* Add the dangling domain to your Heroku app (whose name you will be providing in the .env file)
* And, that's it!


### Future Work

* ~Take CMS name and regex from user or .env file and then automatically hook them into the tool to be able to find it.~ DONE
* Add takeovers for more CMS
* Add more CMS providers


### Credits

* Thanks to Luke Young (@TheBoredEng) for helping me out with the go-github library.
* Thanks to Frans Rosen (@fransrosen) for helping me understand the technical details that are required for some of the takeovers.
* Thanks to Mohammed Diaa (@mhmdiaa) for taking time to implement the provider data functionality and getting the code going.


### Changelog

`6/25`
* Made the code much more faster by implementing goroutines
* Instead of checking using Golang's net packages' LookupCNAME function, made it to just use dig since that gives you dead DNS records as well. More attack surface!!

