package droxo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
)

var (
	config   oauth2.Config
	provider *oidc.Provider
)

type Service struct {
	Profile string
	APIKeys map[string]string
	LogoKey string
}

func DefineClient(clientId, clientSecret, host, authHost string, scopes ...string) {
	prov, err := oidc.NewProvider(context.Background(), authHost)

	if err != nil {
		panic(err)
	}

	provider = prov

	config = oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		RedirectURL:  fmt.Sprintf("https://%s.%s/oauth2", clientId, host),
		Endpoint:     provider.Endpoint(),
	}
}

func AuthStart(c *gin.Context) {
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

	//session := sessions.Default(c)

	session.Set("state", state)
	err = session.Save()

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	responseType := oauth2.SetAuthURLParam("response_type", "code")
	c.Redirect(http.StatusTemporaryRedirect, config.AuthCodeURL(state, responseType))
}

func AuthCallback(c *gin.Context) {
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

	token, err := config.Exchange(context.Background(), code)

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	if len(token.RefreshToken) > 0 {
		session.Set("refresh_token", token.RefreshToken)
	}

	session.Set("access_token", token.AccessToken)

	err = session.Save()

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	c.Redirect(http.StatusSeeOther, "/")
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
func Wrap(name string, oper Service, result interface{}) gin.H {
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
