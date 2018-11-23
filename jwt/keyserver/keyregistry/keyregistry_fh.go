// Copyright 2016 CoreOS, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build fasthttp

package keyregistry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	//"io/ioutil"
	//"net/http"
	"net/url"
	"path"
	"strconv"
	"sync"
	"time"
	"bufio"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/key"
	//"github.com/gregjones/httpcache"
	"gopkg.in/yaml.v2"

	"github.com/coreos/jwtproxy/config"
	"github.com/coreos/jwtproxy/jwt"
	"github.com/coreos/jwtproxy/jwt/keyserver"
	"github.com/coreos/jwtproxy/jwt/keyserver/keyregistry/keycache"
	"github.com/valyala/fasthttp"
)

func init() {
	keyserver.RegisterReader("keyregistry", constructReader)
	keyserver.RegisterManager("keyregistry", constructManager)
}

type client struct {
	cache        keycache.Cache
	registry     *url.URL
	signerParams config.SignerParams
	stopping     chan struct{}
	inFlight     *sync.WaitGroup
	httpClient   *fasthttp.Client
}

type Config struct {
	Registry config.URL `yaml:"registry"`
}

type ReaderConfig struct {
	Config `yaml:",inline"'`
	Cache  *config.RegistrableComponentConfig `yaml:"cache"`
}

func (krc *client) GetPublicKey(issuer string, keyID string) (*key.PublicKey, error) {
	// Query key registry for a public key matching the given issuer and key ID.
	pubkeyURL := krc.absURL("services", issuer, "keys", keyID)
	pubkeyReq, err := krc.prepareRequest("GET", pubkeyURL, nil)
	if err != nil {
		return nil, err
	}

	resp := fasthttp.AcquireResponse()
	err = krc.httpClient.Do(pubkeyReq, resp)
	if err != nil {
		return nil, err
	}
	defer resp.ConnectionClose()

	if resp.StatusCode() != fasthttp.StatusOK {
		switch resp.StatusCode() {
		case fasthttp.StatusNotFound:
			return nil, keyserver.ErrPublicKeyNotFound
		case fasthttp.StatusForbidden:
			return nil, keyserver.ErrPublicKeyExpired
		default:
			//bodyBytes, bodyErr := ioutil.ReadAll(resp.bodyStream)
			//bodyBytes, bodyErr := ioutil.ReadAll(resp.Body())
			//bodyBytes, bodyErr := ioutil.ReadAll(resp.Body)
			bodyBytes := resp.Body()
			//log.Debug("KEYYYYYYYYYYY*- response from key server: %v: %s", resp.StatusCode(), string(bodyBytes))
/* TODO - check later and fix 
			if bodyErr != nil {
				bodyBytes = []byte{}
			}
*/

			rerr := fmt.Errorf("Got unexpected response from key server: %v: %s", resp.StatusCode(), string(bodyBytes))
			return nil, rerr
		}
	}

	// Decode the public key we received as a JSON-encoded JWK.
	var pk key.PublicKey
	jsonDecoder := json.NewDecoder(bytes.NewBuffer(resp.Body()))
	err = jsonDecoder.Decode(&pk)
	if err != nil {
		return nil, err
	}

	return &pk, nil
}

func (krc *client) VerifyPublicKey(keyID string) error {
	_, err := krc.GetPublicKey(krc.signerParams.Issuer, keyID)
	return err
}

func (krc *client) PublishPublicKey(key *key.PublicKey, policy *keyserver.KeyPolicy, signingKey *key.PrivateKey) *keyserver.PublishResult {
	// Create a channel that will track the response status.
	publishResult := keyserver.NewPublishResult()
	krc.inFlight.Add(1)

	go func() {
		defer krc.inFlight.Done()
		// Serialize the jwk as the body.
		body, err := json.Marshal(key)
		if err != nil {
			publishResult.SetError(err)
			return
		}

		// Create an HTTP request to the key server to publish a new key.
		publishURL := krc.absURL("services", krc.signerParams.Issuer, "keys", key.ID())

		queryParams := publishURL.Query()
		if policy.Expiration != nil {
			log.Debug("Adding expiration time: ", policy.Expiration)
			queryParams.Add("expiration", strconv.FormatInt(policy.Expiration.Unix(), 10))
		}
		if policy.RotationPolicy != nil {
			log.Debug("Adding rotation time: ", policy.RotationPolicy)
			queryParams.Add("rotation", strconv.Itoa(int(policy.RotationPolicy.Seconds())))
		}
		publishURL.RawQuery = queryParams.Encode()

		resp, err := krc.signAndDo("PUT", publishURL, bytes.NewReader(body), signingKey)
		if err != nil {
			publishResult.SetError(err)
			return
		}

		switch resp.StatusCode() {
		case fasthttp.StatusOK:
			// Published successfully.
			publishResult.Success()
			return
		case fasthttp.StatusAccepted:
			monPublishLog := log.WithFields(log.Fields{
				"keyID":        key.ID()[0:10],
				"signingKeyID": signingKey.ID()[0:10],
			})

			// Our key couldn't be published immediately because it requires
			// approval. Loop until it becomes approved or the whole process
			// gets canceled.
			monPublishLog.Debug("Monitoring publish status")
			monURL := krc.absURL("services", krc.signerParams.Issuer, "keys", key.ID())

			pollPeriod := time.NewTicker(1 * time.Second)
			defer pollPeriod.Stop()

			for {
				select {
				case <-pollPeriod.C:
					checkReq, err := krc.prepareRequest("GET", monURL, nil)
					if err != nil {
						publishResult.SetError(err)
						return
					}
					resp := fasthttp.AcquireResponse()
					err = krc.httpClient.Do(checkReq, resp)
					if err != nil {
						publishResult.SetError(err)
						return
					}

					switch resp.StatusCode() {
					case fasthttp.StatusOK:
						publishResult.Success()
						return
					case fasthttp.StatusConflict:
						monPublishLog.Debug("Key not yet approved, waiting")
					default:
						checkPublishedErr := fmt.Errorf(
							"Unexpected response code when checking approval status %d",
							resp.StatusCode(),
						)
						publishResult.SetError(checkPublishedErr)
						return
					}

				case <-publishResult.WaitForCancel():
					monPublishLog.Debug("Canceling key publication monitor goroutine")
					canceledErr := fmt.Errorf("Key publication monitor canceled")
					publishResult.SetError(canceledErr)
					return
				case <-krc.stopping:
					monPublishLog.Debug("Candeling key publication due to shutdown")
					shutdownErr := fmt.Errorf("Shutting down")
					publishResult.SetError(shutdownErr)
					return
				}
			}

		default:
			publishServerError := fmt.Errorf(
				"Unexpected response code when publishing key: %d ",
				resp.StatusCode,
			)
			publishResult.SetError(publishServerError)
			return
		}
	}()

	return publishResult
}

func (krc *client) DeletePublicKey(signingKey *key.PrivateKey) error {
	url := krc.absURL("services", krc.signerParams.Issuer, "keys", signingKey.ID())

	resp, err := krc.signAndDo("DELETE", url, nil, signingKey)
	if err != nil {
		return err
	}

	if resp.StatusCode() != 204 {
		return fmt.Errorf("Unexpected response code when deleting public key: %d", resp.StatusCode)
	}

	return nil
}

func (krc *client) Stop() <-chan struct{} {
	finished := make(chan struct{})
	// Stop the in flight requests
	close(krc.stopping)
	go func() {
		krc.inFlight.Wait()

		// Now stop the cache
		if krc.cache != nil {
			<-krc.cache.Stop()
		}

		close(finished)
	}()
	return finished
}

func (krc *client) signAndDo(method string, url *url.URL, body io.Reader, signingKey *key.PrivateKey) (*fasthttp.Response, error) {
	// Create an HTTP request to the key server to publish a new key.
	req, err := krc.prepareRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	// Sign it with the specified private key and config.
	err = jwt.Sign1(req, signingKey, krc.signerParams) //fasthttp.Request
	if err != nil {
		return nil, err
	}

	// Execute the request, if it returns a 200, close the channel immediately.
	resp := fasthttp.AcquireResponse()
	err = krc.httpClient.Do(req, resp)
	return resp, err
}

func (krc *client) prepareRequest(method string, url *url.URL, body io.Reader) (*fasthttp.Request, error) {
	// Create an HTTP request to the key server to publish a new key.
	//req, err := http.NewRequest(method, url.String(), body)
	req := fasthttp.AcquireRequest()
        req.SetRequestURI(url.String())
	err := req.Read(bufio.NewReader(body))

	if err != nil {
		return nil, err
	}

	if method == "PUT" || method == "POST" {
		req.Header.Add("Content-Type", "application/json")
	}

	// Add our user agent.
	req.Header.Set("User-Agent", "KeyRegistryClient/0.1.0")

	return req, nil
}

func (krc *client) absURL(pathParams ...string) *url.URL {
	escaped := make([]string, 0, len(pathParams)+1)
	escaped = append(escaped, krc.registry.Path)
	for _, pathParam := range pathParams {
		escaped = append(escaped, url.QueryEscape(pathParam))
	}

	absPath := path.Join(escaped...)
	relurl, err := url.Parse(absPath)
	if err != nil {
		panic(err)
	}
	return krc.registry.ResolveReference(relurl)
}

func constructReader(registrableComponentConfig config.RegistrableComponentConfig) (keyserver.Reader, error) {
	fmt.Println("constructReader")
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, err
	}
	var cfg ReaderConfig
	err = yaml.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}

	// Construct the public key cache.
	cacheConfig := config.RegistrableComponentConfig{
		Type: "memory",
	}
	if cfg.Cache != nil {
		cacheConfig = *cfg.Cache
	}

	cache, err := keycache.NewCache(cacheConfig)
	if err != nil {
		return nil, fmt.Errorf("Unable to construct cache: %s", err)
	}

	httpClient := &fasthttp.Client{
		// TODO - fix this later
		// Transport: httpcache.NewTransport(cache),
	}

	return &client{
		registry:   cfg.Registry.URL,
		inFlight:   &sync.WaitGroup{},
		stopping:   make(chan struct{}),
		cache:      cache,
		httpClient: httpClient,
	}, nil
}

func constructManager(registrableComponentConfig config.RegistrableComponentConfig, signerParams config.SignerParams) (keyserver.Manager, error) {
	fmt.Println("*** constructManager")
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}

	DefaultClient := &fasthttp.Client{
		// TODO - fix this later
		// Transport: httpcache.NewTransport(cache),
	}
	return &client{
		registry:     cfg.Registry.URL,
		signerParams: signerParams,
		inFlight:     &sync.WaitGroup{},
		stopping:     make(chan struct{}),
		//httpClient:   http.DefaultClient,
		httpClient:   DefaultClient,
	}, nil
}
