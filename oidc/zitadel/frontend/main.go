package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
	openid "github.com/zitadel/zitadel-go/v3/pkg/authentication/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	// flags to be provided for running the example server
	domain      = flag.String("domain", "zitadel.dev.honganh.vn", "your ZITADEL instance domain (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	key         = flag.String("key", "14d67567f09d56fd2d084cbcad6b4102", "encryption key")
	clientID    = flag.String("clientID", "303595230391763018", "clientID provided by ZITADEL")
	redirectURI = flag.String("redirectURI", "http://localhost:8090/auth/callback", "redirectURI registered at ZITADEL")
	port        = flag.String("port", "8090", "port to run the server on (default is 8089)")

	//go:embed "templates/*.html"
	templates embed.FS

	// base url backend
	baseURLBe = "http://localhost:8091/api"
)

func main() {
	flag.Parse()

	ctx := context.Background()

	t, err := template.New("").ParseFS(templates, "templates/*.html")
	if err != nil {
		slog.Error("unable to parse template", "error", err)
		os.Exit(1)
	}

	// init authentication
	authN, err := authentication.New(ctx, zitadel.New(*domain), *key,
		openid.DefaultAuthentication(*clientID, *redirectURI, *key),
	)
	if err != nil {
		slog.Error("zitadel sdk could not initialize", "error", err)
		os.Exit(1)
	}

	// init middleware
	mw := authentication.Middleware(authN)

	router := http.NewServeMux()

	router.Handle("/auth/", authN)

	router.Handle("/", mw.CheckAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		err = t.ExecuteTemplate(w, "home.html", nil)
		if err != nil {
			slog.Error("error writing home page response", "error", err)
		}

		// if authentication.IsAuthenticated(req.Context()) {
		// 	userInfo := mw.Context(req.Context())
		// 	fmt.Println("access token: ", userInfo.Tokens.AccessToken)
		// }
	})))

	router.Handle("/tasks", mw.CheckAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !authentication.IsAuthenticated(req.Context()) {
			http.Redirect(w, req, "/", http.StatusUnauthorized)
			return
		}

		userInfo := mw.Context(req.Context())

		fullURL := fmt.Sprintf("%s/tasks", baseURLBe)
		reqBE, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		// add header
		reqBE.Header.Add("Content-Type", "application/json")
		reqBE.Header.Add("Authorization", fmt.Sprintf("Bearer %s", userInfo.Tokens.AccessToken))
		fmt.Println(userInfo.UserInfo.Claims["user_id"])
		fmt.Println(userInfo.Tokens.IDTokenClaims.Claims["user_id"])
		fmt.Println(userInfo.Tokens.IDToken)

		// request
		client := &http.Client{}
		resp, err := client.Do(reqBE)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return
		}
		defer resp.Body.Close()

		// response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response:", err)
			return
		}

		fmt.Fprint(w, string(body))
	})))

	router.Handle("/add-task", mw.CheckAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		userInfo := mw.Context(req.Context())

		fullURL := fmt.Sprintf("%s/add-task", baseURLBe)

		// add body
		formData := url.Values{}
		formData.Set("task", "hoang-cao-long")

		reqBE, err := http.NewRequest("POST", fullURL, strings.NewReader(formData.Encode()))
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		// add header
		reqBE.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		reqBE.Header.Add("Authorization", fmt.Sprintf("Bearer %s", userInfo.Tokens.AccessToken))

		// send request
		client := &http.Client{}
		resp, err := client.Do(reqBE)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return
		}
		defer resp.Body.Close()

		// response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response:", err)
			return
		}

		fmt.Fprint(w, string(body))
	})))

	router.Handle("/profile", mw.RequireAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		userInfo := mw.Context(req.Context())

		fmt.Println(userInfo.Tokens.TokenType)

		slog.Info("user info claims:", userInfo.UserInfo.Claims["hoang-cao-long1"])
		slog.Info("user info claims:", userInfo.UserInfo.Claims["name1"])

		userInfoData, err := json.MarshalIndent(userInfo.UserInfo, "", "	")
		if err != nil {
			slog.Error("error marshalling profile response", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = t.ExecuteTemplate(w, "profile.html", string(userInfoData))
		if err != nil {
			slog.Error("error writing profile response", "error", err)
		}
	})))

	router.Handle("/user/create", mw.RequireAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		userInfo := mw.Context(req.Context())

		fullURL := fmt.Sprintf("%s/user/create", baseURLBe)

		// add body
		formData := url.Values{}

		reqBE, err := http.NewRequest("POST", fullURL, strings.NewReader(formData.Encode()))
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		// add header
		reqBE.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		reqBE.Header.Add("Authorization", fmt.Sprintf("Bearer %s", userInfo.Tokens.AccessToken))

		// send request
		client := &http.Client{}
		resp, err := client.Do(reqBE)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return
		}
		defer resp.Body.Close()

		fmt.Fprint(w, "Create user")
	})))

	router.Handle("/user/update", mw.RequireAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		userInfo := mw.Context(req.Context())

		fullURL := fmt.Sprintf("%s/user/update", baseURLBe)

		// add body
		formData := url.Values{}

		reqBE, err := http.NewRequest("POST", fullURL, strings.NewReader(formData.Encode()))
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		// add header
		reqBE.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		reqBE.Header.Add("Authorization", fmt.Sprintf("Bearer %s", userInfo.Tokens.AccessToken))

		// send request
		client := &http.Client{}
		resp, err := client.Do(reqBE)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return
		}
		defer resp.Body.Close()

		fmt.Fprint(w, "Update user")
	})))

	router.Handle("/user/change-password", mw.RequireAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		userInfo := mw.Context(req.Context())

		fullURL := fmt.Sprintf("%s/user/change-password", baseURLBe)

		// add body
		formData := url.Values{}

		reqBE, err := http.NewRequest("POST", fullURL, strings.NewReader(formData.Encode()))
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		// add header
		reqBE.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		reqBE.Header.Add("Authorization", fmt.Sprintf("Bearer %s", userInfo.Tokens.AccessToken))

		// send request
		client := &http.Client{}
		resp, err := client.Do(reqBE)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return
		}
		defer resp.Body.Close()

		fmt.Fprint(w, "Change password user")
	})))

	router.Handle("/user/deactivate", mw.RequireAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		userInfo := mw.Context(req.Context())

		fullURL := fmt.Sprintf("%s/user/deactivate", baseURLBe)

		// add body
		formData := url.Values{}

		reqBE, err := http.NewRequest("POST", fullURL, strings.NewReader(formData.Encode()))
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		// add header
		reqBE.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		reqBE.Header.Add("Authorization", fmt.Sprintf("Bearer %s", userInfo.Tokens.AccessToken))

		// send request
		client := &http.Client{}
		resp, err := client.Do(reqBE)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return
		}
		defer resp.Body.Close()

		fmt.Fprint(w, "Deactivate user")
	})))

	lis := fmt.Sprintf(":%s", *port)
	slog.Info("server listening, press ctrl+c to stop", "addr", "http://localhost"+lis)
	err = http.ListenAndServe(lis, router)
	if !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server terminated", "error", err)
		os.Exit(1)
	}
}
