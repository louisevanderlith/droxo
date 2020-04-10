package droxo

import (
	"encoding/json"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func AuthorizeClient(clientId, clientSecret, introspectUrl string) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		if accesstokn := session.Get("access_token"); accesstokn != nil {
			c.Set("profile", loadProfile(accesstokn.(string), clientId, clientSecret, introspectUrl))
			c.Next()
		} else {
			c.Redirect(http.StatusSeeOther, "/login")
		}
	}
}

func AuthorizeReally(cfg oauth2.Config) gin.HandlerFunc {
	infoUrl := strings.Replace(cfg.Endpoint.TokenURL, "token", "info", 1)
	return func(c *gin.Context) {
		session := sessions.Default(c)

		if jstoken := session.Get("full_token"); jstoken != nil {
			ftokn := &oauth2.Token{}
			err := json.Unmarshal(jstoken.([]byte), ftokn)

			if err != nil {
				log.Println(err)
				c.AbortWithError(http.StatusInternalServerError, err)
			}

			if !ftokn.Valid() {
				c.Redirect(http.StatusSeeOther, "/login")
				return
			}

			c.Set("profile", loadProfile(ftokn.AccessToken, cfg.ClientID, cfg.ClientSecret, infoUrl))
			c.Next()
		} else {
			c.Redirect(http.StatusSeeOther, "/login")
		}
	}
}

func loadProfile(accessToken, clientId, clientSecret, introspectUrl string) interface{} {
	form := url.Values{}
	form.Add("access_code", accessToken)
	req, err := http.NewRequest("POST", introspectUrl, strings.NewReader(form.Encode()))

	if err != nil {
		log.Println("Failed to make new Request", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientId, clientSecret)

	client := &http.Client{Timeout: time.Second * 10}

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error reading response. ", err)
		return nil
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)

	var info interface{}
	err = dec.Decode(&info)

	if err != nil {
		log.Println(err)
		return nil
	}

	return info
}

func Authorize(scope, scopesecret, authority string) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqToken := c.GetHeader("Authorization")

		if len(reqToken) == 0 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		splitToken := strings.Split(reqToken, "Bearer")
		if len(splitToken) != 2 {
			log.Println("bad request")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		form := url.Values{
			"scope":        {scope},
			"scope_secret": {scopesecret},
		}
		req, err := http.NewRequest("POST", fmt.Sprintf("%s/validate", authority), strings.NewReader(form.Encode()))

		if err != nil {
			log.Println("Failed to make new Request", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", reqToken)

		client := &http.Client{Timeout: time.Second * 10}

		resp, err := client.Do(req)
		if err != nil {
			log.Println("Error reading response. ", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		defer resp.Body.Close()

		dec := json.NewDecoder(resp.Body)

		result := make(map[string]interface{})
		err = dec.Decode(&result)

		if err != nil {
			log.Println(err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		//TODO: Validate claims
		//[Access:eyJhbGciOiJIUzUx.. AccessCreateAt:2020-01-13T20:43:36.113973491Z AccessExpiresIn:7.2e+12 ClientID:www Code: CodeCreateAt:0001-01-01T00:00:00Z CodeExpiresIn:0 RedirectURI: Refresh: RefreshCreateAt:0001-01-01T00:00:00Z RefreshExpiresIn:0 Scope:offline_access UserID:
		log.Println("full_claims", result)
		actv, ok := result["active"]

		if !ok {
			log.Println("active not in token")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if !actv.(bool){
			log.Println("Active Failed")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		clntId, ok := result["client_id"]

		if !ok {
			log.Println("client_id not in token")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set("client", clntId)
		c.Set("full", result)
	}
}
