package droxo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
)

var (
	config    oauth2.Config
	globToken *oauth2.Token
	Oper      service
)

type service struct {
	Profile string
	Host    string
	LogoKey string
}

func AssignOperator(profile, host string) {
	Oper = service{
		Profile: profile,
		Host:    fmt.Sprintf(".%s/", host),
		LogoKey: "0`0",
	}
}

func DefineClient(clientId, clientSecret, host, authHost string) {
	config = oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes:       []string{"blog", "comms"},
		RedirectURL:  host + "/oauth2",
		Endpoint: oauth2.Endpoint{
			AuthURL:  authHost + "/auth",
			TokenURL: authHost + "/token",
		},
	}
}

func AuthCallback(c *gin.Context) {
	c.Request.ParseForm()
	state := c.Request.Form.Get("state")
	if state != "xyz" {
		c.AbortWithError(http.StatusBadRequest, errors.New("state invalid"))
	}

	code := c.Request.Form.Get("code")
	if code == "" {
		c.AbortWithError(http.StatusBadRequest, errors.New("code not found"))
	}

	token, err := config.Exchange(context.Background(), code)

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
	}

	globToken = token

	e := json.NewEncoder(c.Writer)
	e.SetIndent("", "  ")
	e.Encode(token)
}

func Wrap(name string, result interface{}) gin.H {
	lname := strings.ToLower(name)
	jstmpl := lname + ".js"

	return gin.H{
		"Title":      fmt.Sprintf("%s - %s", name, Oper.Profile),
		"Data":       result,
		"Oper":       Oper,
		"HasScript":  true,
		"ScriptName": jstmpl,
	}
}
