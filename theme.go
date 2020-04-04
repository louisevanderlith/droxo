package droxo

import (
	"context"
	"encoding/json"
	"github.com/gin-contrib/multitemplate"
	"golang.org/x/oauth2/clientcredentials"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func LoadTemplates(templatesDir string) (multitemplate.Renderer, error) {
	r := multitemplate.NewRenderer()

	layouts, err := filepath.Glob(templatesDir + "/_shared/*.html")

	if err != nil {
		return nil, err
	}

	includes, err := filepath.Glob(templatesDir + "/*.html")

	if err != nil {
		return nil, err
	}

	// Generate our templates map from our layouts/ and includes/ directories
	for _, include := range includes {
		layoutCopy := make([]string, len(layouts))
		copy(layoutCopy, layouts)
		files := append(layoutCopy, include)
		base := filepath.Base(include)

		r.AddFromFiles(base, files...)
	}

	return r, nil
}

func UpdateTheme(cfg clientcredentials.Config, url string) error {
	clnt := cfg.Client(context.Background())
	resp, err := clnt.Get(url + "/asset/html")

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	var items []string
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&items)

	if err != nil {
		return err
	}

	for _, v := range items {
		err = downloadFile(url, v)

		if err != nil {
			return err
		}
	}

	return nil
}

func downloadFile(url, templ string) error {
	resp, err := http.Get(url + "/asset/html/" + templ)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	out, err := os.Create("/views/_shared/" + templ)

	if err != nil {
		return err
	}

	defer out.Close()

	_, err = io.Copy(out, resp.Body)

	return err
}
