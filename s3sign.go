package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var id, key string
var duration time.Duration
var method string

// Query parameters that should be used in signing the request.
var canonParams = map[string]bool{
	"acl":                          true,
	"delete":                       true,
	"lifecycle":                    true,
	"location":                     true,
	"logging":                      true,
	"notification":                 true,
	"partnumber":                   true,
	"policy":                       true,
	"requestpayment":               true,
	"response-cache-control":       true,
	"response-content-disposition": true,
	"response-content-encoding":    true,
	"response-content-language":    true,
	"response-content-type":        true,
	"response-expires":             true,
	"torrent":                      true,
	"uploadid":                     true,
	"uploads":                      true,
	"versionid":                    true,
	"versioning":                   true,
	"versions":                     true,
	"website":                      true,
}

func main() {
	flag.StringVar(&id, "id", "", "access key")
	flag.StringVar(&key, "key", "", "secret key")
	flag.DurationVar(&duration, "d", time.Hour, "duration to expiration")
	flag.StringVar(&method, "method", "GET", "HTTP method to sign for")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: s3sign <url>")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	expires := time.Now().Add(duration).Unix()

	for _, a := range flag.Args() {
		u, err := url.Parse(a)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}

		sig := sign(u, expires)

		q := u.Query()
		q.Set("AWSAccessKeyId", id)
		q.Set("Expires", strconv.FormatInt(expires, 10))
		q.Set("Signature", sig)
		u.RawQuery = q.Encode()

		fmt.Println(u)
	}
}

func sign(u *url.URL, expires int64) string {
	hmac := hmac.New(sha1.New, []byte(key))
	fmt.Fprintf(hmac, "%s\n\n\n%d\n%s", method, expires, canonicalizedResource(u))
	return base64.StdEncoding.EncodeToString(hmac.Sum(nil))
}

func canonicalizedResource(u *url.URL) string {
	if q := canonicalizedQuery(u.Query()); q != "" {
		return u.EscapedPath() + "?" + q
	}
	return u.EscapedPath()
}

func canonicalizedQuery(query url.Values) string {
	for k := range query {
		if !canonParams[strings.ToLower(k)] {
			delete(query, k)
		}
	}
	return query.Encode()
}
