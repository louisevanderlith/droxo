package droxo

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"strings"
)

var (
	config    oauth2.Config
	globToken *oauth2.Token
	provider  *oidc.Provider
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

func DefineClient(clientId, clientSecret, host, authHost string, scopes ...string) {
	prov, err := oidc.NewProvider(context.Background(),authHost)

	if err != nil {
		panic(err)
	}

	provider = prov

	config = oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		RedirectURL:  host + "/oauth2",
		Endpoint: provider.Endpoint(),
	}
}

func AuthCallback(c *gin.Context) {
	c.Request.ParseForm()
	state := c.Request.Form.Get("state")

	session := sessions.Default(c)

	cstate := session.Get("state")

	if state != cstate {
		c.AbortWithError(http.StatusBadRequest, errors.New("state invalid"))
		return
	}

	code := c.Request.Form.Get("code")
	if code == "" {
		c.AbortWithError(http.StatusBadRequest, errors.New("code not found"))
		return
	}

	token, err := config.Exchange(context.Background(), code)

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	globToken = token

	rawIDToken, ok := token.Extra("id_token").(string)

	if !ok {
		c.AbortWithError(http.StatusInternalServerError, errors.New("No id_token field in oauth2 token."))
		return
	}

	oidcConfig := &oidc.Config{
		ClientID: config.ClientID,
	}

	idToken, err := provider.Verifier(oidcConfig).Verify(c.Copy(), rawIDToken)

	if err != nil {
		log.Println("Failed to verify ID Token: " + err.Error())
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	var profile map[string]interface{}
	if err := idToken.Claims(&profile); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	session.Set("id_token", rawIDToken)
	session.Set("access_token",token.AccessToken)
	session.Set("profile",profile)

	err = session.Save()

	if err != nil{
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	c.Redirect(http.StatusSeeOther, "/")
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
