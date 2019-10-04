package httpserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"k8s.io/klog"
)

type Server struct {
	UriToResponse map[string]string
	ListenAddr    string

	server http.Server
}

func (h *Server) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	uri := strings.Split(r.Host, ":")[0] + r.URL.String()
	response, found := h.UriToResponse[uri]
	klog.V(4).Infof("URI %q %sfound", uri, func() string {
		if !found {
			return "not "
		}
		return ""
	}())

	if found {
		w.WriteHeader(http.StatusOK)
		_, err := fmt.Fprint(w, response)
		if err != nil {
			klog.Errorf("unable to write response")
		}
		return
	}

	w.WriteHeader(http.StatusNotFound)

	return
}

func (h *Server) ParseData(data []byte) error {
	lines := strings.Split(string(data), "\n")
	klog.Infof("Parsing %d line(s)", len(lines))
	for n, l := range lines {
		if len(strings.TrimSpace(l)) == 0 {
			continue
		}

		parts := strings.SplitN(l, " ", 2)
		if len(parts) != 2 {
			// don't print the content as it contains secret data
			return fmt.Errorf("can't parse line %d", n)
		}
		uri := parts[0]
		response := parts[1]
		h.UriToResponse[uri] = response
	}

	return nil
}

func (h *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handler)
	h.server.Handler = mux
	h.server.Addr = h.ListenAddr

	listener, err := net.Listen("tcp", h.server.Addr)
	if err != nil {
		return err
	}

	// if you don't specify addr (e.g. port) we need to find to which it was bound so e.g. tests can use it
	h.ListenAddr = listener.Addr().String()
	klog.V(1).Infof("Http-01: server listening on http://%s/", h.ListenAddr)

	err = h.server.Serve(listener)
	if err == http.ErrServerClosed {
		klog.Infof("Server closed gracefully")
		return nil
	}
	return err
}

func (h *Server) Shutdown(ctx context.Context) error {
	klog.Infof("Shutting down server...")
	defer klog.Infof("Server shut down")

	return h.server.Shutdown(ctx)
}
