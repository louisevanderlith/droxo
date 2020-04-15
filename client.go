package droxo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"net/http"
	"strings"
)

type Op struct {
	Profile  string
	APIKeys  map[string]string
	LogoKey  string
	Username string
	LoggedIn bool
	GTag     string
}

//AuthenticateClient will return a token for the current client
func AuthenticateClient(clientId, clientSecret, authority string, scopes ...string) clientcredentials.Config {
	return clientcredentials.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		TokenURL:     authority + "/token",
		Scopes:       scopes,
		AuthStyle:    oauth2.AuthStyleInParams,
	}
}

//PrepareClientUser will return a config for the current client, to be used for user authentication
func PrepareClientUser(clientId, clientSecret, authority, redirect string, scopes ...string) oauth2.Config {
	return oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		RedirectURL:  redirect,
		Endpoint:     oauth2.Endpoint{TokenURL: authority + "/token", AuthURL: authority + "/authorize"},
	}
}

func AuthStart(cfg oauth2.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		if session.Get("profile") != nil {
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

		session.Set("state", state)
		err = session.Save()

		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		responseType := oauth2.SetAuthURLParam("response_type", "code")
		c.Redirect(http.StatusTemporaryRedirect, cfg.AuthCodeURL(state, responseType))
	}
}

func AuthCallback(cfg oauth2.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.ParseForm()
		state := c.Query("state")

		session := sessions.Default(c)

		cstate := session.Get("state")

		if state != cstate {
			c.AbortWithError(http.StatusBadRequest, errors.New("state invalid"))
			return
		}

		code := c.Query("code")
		if code == "" {
			c.AbortWithError(http.StatusBadRequest, errors.New("code not found"))
			return
		}

		token, err := cfg.Exchange(context.Background(), code)

		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		jsTokn, err := json.Marshal(token)

		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		session.Set("full_token", jsTokn)
		session.Set("access_token", token.AccessToken)

		err = session.Save()

		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.Redirect(http.StatusSeeOther, "/")
	}
}

func Wrap(name string, oper Op, result interface{}) gin.H {
	lname := strings.ToLower(name)
	jstmpl := lname + ".js"

	return gin.H{
		"Title":      fmt.Sprintf("%s - %s", name, oper.Profile),
		"Data":       result,
		"Oper":       oper,
		"HasScript":  true,
		"ScriptName": jstmpl,
	}
}

/*
func Logout(c *gin.Context) {
	domain := "YOUR_DOMAIN"

	logoutUrl, err := url.Parse("https://" + domain)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logoutUrl.Path += "/v2/logout"
	parameters := url.Values{}

	var scheme string
	if r.TLS == nil {
		scheme = "http"
	} else {
		scheme = "https"
	}

	returnTo, err := url.Parse(scheme + "://" +  r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	parameters.Add("returnTo", returnTo.String())
	parameters.Add("client_id", "YOUR_CLIENT_ID")
	logoutUrl.RawQuery = parameters.Encode()

	http.Redirect(w, r, logoutUrl.String(), http.StatusTemporaryRedirect)
}
*/
