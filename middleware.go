package droxo

import (
	"encoding/json"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func AuthorizeClient(introspectUrl string) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		if accesstokn := session.Get("access_token"); accesstokn != nil {
			c.Set("profile", loadProfile(accesstokn.(string), introspectUrl))
			c.Next()
		} else {
			c.Redirect(http.StatusSeeOther, "/login")
		}
	}
}

func loadProfile(accessToken, introspectUrl string) interface{} {
	form := url.Values{}
	form.Add("access_code", accessToken)
	req, err := http.NewRequest("POST", introspectUrl, strings.NewReader(form.Encode()))

	if err != nil {
		log.Println("Failed to make new Request", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.ClientID, config.ClientSecret)

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

func Authorize() gin.HandlerFunc {
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

		data := url.Values{
			"token": {strings.Trim(splitToken[1], " ")},
		}
		log.Println("Encode token:", data.Encode())
		resp, err := http.PostForm(fmt.Sprintf("https://oauth2%sinfo", Oper.Host), data)

		if err != nil {
			log.Println(err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Println("not ok", resp.StatusCode)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		result := make(map[string]interface{})
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&result)

		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		//TODO: Validate claims
		//[Access:eyJhbGciOiJIUzUx.. AccessCreateAt:2020-01-13T20:43:36.113973491Z AccessExpiresIn:7.2e+12 ClientID:www Code: CodeCreateAt:0001-01-01T00:00:00Z CodeExpiresIn:0 RedirectURI: Refresh: RefreshCreateAt:0001-01-01T00:00:00Z RefreshExpiresIn:0 Scope:offline_access UserID:

		clientId := result["ClientID"].(string)

		if len(clientId) == 0 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set("client", clientId)
	}
}
