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

package jwt

import (
	"errors"
	"fmt"
	"net"
	//"net/http"
	"net/url"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/goproxy"

	"github.com/coreos/jwtproxy/config"
	"github.com/coreos/jwtproxy/jwt/claims"
	"github.com/coreos/jwtproxy/jwt/keyserver"
	"github.com/coreos/jwtproxy/jwt/noncestorage"
	"github.com/coreos/jwtproxy/jwt/privatekey"
	"github.com/coreos/jwtproxy/proxy"
	"github.com/coreos/jwtproxy/stop"
	"github.com/valyala/fasthttp"
)

type StoppableProxyHandler struct {
	proxy.Handler
	stopFunc func() <-chan struct{}
}

func NewJWTSignerHandler(cfg config.SignerConfig) (*StoppableProxyHandler, error) {
	// Verify config (required keys that have no defaults).
	if cfg.PrivateKey.Type == "" {
		return nil, errors.New("no private key provider specified")
	}

	// Get the private key that will be used for signing.
	privateKeyProvider, err := privatekey.New(cfg.PrivateKey, cfg.SignerParams)
	if err != nil {
		return nil, err
	}

	// Create a proxy.Handler that will add a JWT to http.Requests.
	handler := func(r *fasthttp.RequestCtx, ctx *goproxy.ProxyCtx) (*fasthttp.RequestCtx, error) {
		privateKey, err := privateKeyProvider.GetPrivateKey()
		if err != nil {
			//return r, errorResponse(r, err)
			return r, err
		}

		if err := Sign(r, privateKey, cfg.SignerParams); err != nil {
			//return r, errorResponse(r, err)
			return r, err
		}
		return r, nil
	}

	return &StoppableProxyHandler{
		Handler:  handler,
		stopFunc: privateKeyProvider.Stop,
	}, nil
}

func NewJWTVerifierHandler(cfg config.VerifierConfig) (*StoppableProxyHandler, error) {
	// Verify config (required keys that have no defaults).
	if cfg.Upstream.URL == nil {
		return nil, errors.New("no upstream specified")
	}
	if cfg.Audience.URL == nil {
		return nil, errors.New("no audience specified")
	}
	if cfg.KeyServer.Type == "" {
		return nil, errors.New("no key server specified")
	}

	stopper := stop.NewGroup()

	// Create a KeyServer that will provide public keys for signature verification.
	keyServer, err := keyserver.NewReader(cfg.KeyServer)
	if err != nil {
		return nil, err
	}
	stopper.Add(keyServer)

	// Create a NonceStorage that will create nonces for signing.
	nonceStorage, err := noncestorage.New(cfg.NonceStorage)
	if err != nil {
		return nil, err
	}
	stopper.Add(nonceStorage)

	// Create an appropriate routing policy.
	route := newRouter(cfg.Upstream.URL)

	// Create the required list of claims.Verifier.
	var claimsVerifiers []claims.Verifier
	if cfg.ClaimsVerifiers != nil {
		claimsVerifiers = make([]claims.Verifier, 0, len(cfg.ClaimsVerifiers))

		for _, verifierConfig := range cfg.ClaimsVerifiers {
			verifier, err := claims.New(verifierConfig)
			if err != nil {
				return nil, fmt.Errorf("could not instantiate claim verifier: %s", err)
			}

			stopper.Add(verifier)
			claimsVerifiers = append(claimsVerifiers, verifier)
		}
	} else {
		log.Info("No claims verifiers specified, upstream should be configured to verify authorization")
	}

	// Create a reverse proxy.Handler that will verify JWT from http.Requests.
	handler := func(r *fasthttp.RequestCtx, ctx *goproxy.ProxyCtx) (*fasthttp.RequestCtx, error) {
		signedClaims, err := Verify(r, keyServer, nonceStorage, cfg.Audience.URL, cfg.MaxSkew, cfg.MaxTTL)
		if err != nil {
			//return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, fmt.Sprintf("jwtproxy: unable to verify request: %s", err))
			return r, err
		}

		// Run through the claims verifiers.
		for _, verifier := range claimsVerifiers {
			err := verifier.Handle(r, signedClaims)
			if err != nil {
				//return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, fmt.Sprintf("Error verifying claims: %s", err))
				return r, err
			}
		}

		// Route the request to upstream.
		route(r, ctx)

		return r, nil
	}

	return &StoppableProxyHandler{
		Handler:  handler,
		stopFunc: stopper.Stop,
	}, nil
}

func (sph *StoppableProxyHandler) Stop() <-chan struct{} {
	return sph.stopFunc()
}

func errorResponse(r *fasthttp.Request, err error) *fasthttp.Response {
	return goproxy.NewResponse(r, goproxy.ContentTypeText, fasthttp.StatusBadGateway, fmt.Sprintf("jwtproxy: unable to sign request: %s", err))
}

type router func(r *fasthttp.RequestCtx, ctx *goproxy.ProxyCtx)

func newRouter(upstream *url.URL) router {
	if strings.HasPrefix(upstream.String(), "unix:") {
		// Upstream is an UNIX socket.
		// - Use a goproxy.RoundTripper that has an "unix" net.Dial.
		// - Rewrite the request's scheme to be "http" and the host to be the encoded path to the
		//   socket.
		sockPath := strings.TrimPrefix(upstream.String(), "unix:")
		roundTripper := newUnixRoundTripper(sockPath)
		return func(r *fasthttp.RequestCtx, ctx *goproxy.ProxyCtx) {
			ctx.RoundTripper = roundTripper
			r.Request.URI().SetScheme("http")
			r.Request.SetHost(sockPath)
		}
	}

	// Upstream is an HTTP or HTTPS endpoint.
	// - Set the request's scheme and host to the upstream ones.
	// - Prepend the request's path with the upstream path.
	// - Merge query values from request and upstream.
	return func(r *fasthttp.RequestCtx, ctx *goproxy.ProxyCtx) {
		r.URI().SetScheme(upstream.Scheme)
		r.URI().SetHost(upstream.Host)
		r.URI().SetPath(singleJoiningSlash(upstream.Path, string(r.URI().Path())))

		upstreamQuery := upstream.RawQuery
		if upstreamQuery == "" || string(r.URI().QueryString()) == "" {
			r.URI().SetQueryString(upstreamQuery + string(r.URI().QueryString()))
		} else {
			r.URI().SetQueryString(upstreamQuery + "&" + string(r.URI().QueryString()))
		}
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

type unixRoundTripper struct {
	*fasthttp.Transport
}

func newUnixRoundTripper(sockPath string) *unixRoundTripper {
	dialer := func(network, addr string) (net.Conn, error) {
		return net.Dial("unix", sockPath)
	}

	return &unixRoundTripper{
		Transport: &fasthttp.Transport{Dial: dialer},
	}
}

func (urt *unixRoundTripper) RoundTrip(req *fasthttp.RequestCtx, ctx *goproxy.ProxyCtx) (*fasthttp.RequestCtx, error) {
	return urt.Transport.RoundTrip(req)
}
