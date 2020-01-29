package droxo

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func AuthorizeClient() gin.HandlerFunc {
	return func(c *gin.Context) {
		if globToken != nil {
			c.Next()
			return
		}

		// Generate random state
		b := make([]byte, 32)
		_, err := rand.Read(b)

		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		state := base64.StdEncoding.EncodeToString(b)

		session := sessions.Default(c)

		session.Set("state", state)
		err = session.Save()

		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, config.AuthCodeURL(state))
	}
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
		log.Println(data.Encode())
		resp, err := http.PostForm("http://oauth2:8086/info", data)

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
		}

		c.Set("client", clientId)
	}
}
