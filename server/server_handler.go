package chserver

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	chshare "github.com/jpillora/chisel/share"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/settings"
	"github.com/jpillora/chisel/share/tunnel"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

func reverseSessionUser(user *settings.User) string {
	if user == nil {
		return ""
	}
	return user.Name
}

func reverseSessionKey(r *settings.Remote) string {
	return r.LocalProto + ":" + r.Local()
}

func reverseSessionKeys(remotes settings.Remotes) []string {
	keys := make([]string, 0, len(remotes))
	for _, r := range remotes {
		keys = append(keys, reverseSessionKey(r))
	}
	return keys
}

func (s *Server) takeoverReverseSessions(id int32, user string, remotes settings.Remotes) []*reverseSession {
	if len(remotes) == 0 {
		return nil
	}
	victims := map[*reverseSession]struct{}{}
	s.reverseMu.Lock()
	for _, r := range remotes {
		key := reverseSessionKey(r)
		sess := s.reverseIndex[key]
		if sess == nil || sess.id == id || sess.user != user {
			continue
		}
		victims[sess] = struct{}{}
	}
	s.reverseMu.Unlock()
	for sess := range victims {
		s.Infof("Taking over reverse session#%d", sess.id)
		sess.cancel()
	}
	out := make([]*reverseSession, 0, len(victims))
	for sess := range victims {
		out = append(out, sess)
	}
	return out
}

func waitReverseSessions(victims []*reverseSession, timeout time.Duration) bool {
	if len(victims) == 0 {
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for _, sess := range victims {
		select {
		case <-sess.done:
		case <-timer.C:
			return false
		}
	}
	return true
}

func reverseCanListen(remotes settings.Remotes) bool {
	for _, r := range remotes {
		if !r.CanListen() {
			return false
		}
	}
	return true
}

func (s *Server) registerReverseSession(id int32, user string, cancel context.CancelFunc, remotes settings.Remotes) func() {
	keys := reverseSessionKeys(remotes)
	if len(keys) == 0 {
		return func() {}
	}
	sess := &reverseSession{id: id, user: user, cancel: cancel, done: make(chan struct{}), keys: keys}
	s.reverseMu.Lock()
	for _, key := range keys {
		s.reverseIndex[key] = sess
	}
	s.reverseMu.Unlock()
	return func() {
		s.reverseMu.Lock()
		for _, key := range sess.keys {
			if s.reverseIndex[key] == sess {
				delete(s.reverseIndex, key)
			}
		}
		s.reverseMu.Unlock()
		close(sess.done)
	}
}

// handleClientHandler is the main http websocket handler for the chisel server
func (s *Server) handleClientHandler(w http.ResponseWriter, r *http.Request) {
	//websockets upgrade AND has chisel prefix
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	protocol := r.Header.Get("Sec-WebSocket-Protocol")
	if upgrade == "websocket" {
		if protocol == chshare.ProtocolVersion {
			s.handleWebsocket(w, r)
			return
		}
		//print into server logs and silently fall-through
		s.Infof("ignored client connection using protocol '%s', expected '%s'",
			protocol, chshare.ProtocolVersion)
	}
	//proxy target was provided
	if s.reverseProxy != nil {
		s.reverseProxy.ServeHTTP(w, r)
		return
	}
	//no proxy defined, provide access to health/version checks
	switch r.URL.Path {
	case "/health":
		w.Write([]byte("OK\n"))
		return
	case "/version":
		w.Write([]byte(chshare.BuildVersion))
		return
	}
	//missing :O
	w.WriteHeader(404)
	w.Write([]byte("Not found"))
}

// handleWebsocket is responsible for handling the websocket connection
func (s *Server) handleWebsocket(w http.ResponseWriter, req *http.Request) {
	id := atomic.AddInt32(&s.sessCount, 1)
	l := s.Fork("session#%d", id)
	wsConn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		l.Debugf("Failed to upgrade (%s)", err)
		return
	}
	conn := cnet.NewWebSocketConn(wsConn)
	// perform SSH handshake on net.Conn
	l.Debugf("Handshaking with %s...", req.RemoteAddr)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		s.Debugf("Failed to handshake (%s)", err)
		return
	}
	// pull the users from the session map
	var user *settings.User
	if s.users.Len() > 0 {
		sid := string(sshConn.SessionID())
		u, ok := s.sessions.Get(sid)
		if !ok {
			panic("bug in ssh auth handler")
		}
		user = u
		s.sessions.Del(sid)
	}
	// chisel server handshake (reverse of client handshake)
	// verify configuration
	l.Debugf("Verifying configuration")
	// wait for request, with timeout
	var r *ssh.Request
	select {
	case r = <-reqs:
	case <-time.After(settings.EnvDuration("CONFIG_TIMEOUT", 10*time.Second)):
		l.Debugf("Timeout waiting for configuration")
		sshConn.Close()
		return
	}
	failed := func(err error) {
		l.Debugf("Failed: %s", err)
		r.Reply(false, []byte(err.Error()))
	}
	if r.Type != "config" {
		failed(s.Errorf("expecting config request"))
		return
	}
	c, err := settings.DecodeConfig(r.Payload)
	if err != nil {
		failed(s.Errorf("invalid config"))
		return
	}
	serverInbound := c.Remotes.Reversed(true)
	userName := reverseSessionUser(user)
	//print if client and server  versions dont match
	cv := strings.TrimPrefix(c.Version, "v")
	if cv == "" {
		cv = "<unknown>"
	}
	sv := strings.TrimPrefix(chshare.BuildVersion, "v")
	if cv != sv {
		l.Infof("Client version (%s) differs from server version (%s)", cv, sv)
	}
	//validate remotes
	for _, r := range c.Remotes {
		//if user is provided, ensure they have
		//access to the desired remotes
		if user != nil {
			addr := r.UserAddr()
			if !user.HasAccess(addr) {
				failed(s.Errorf("access to '%s' denied", addr))
				return
			}
		}
		//confirm reverse tunnels are allowed
		if r.Reverse && !s.config.Reverse {
			l.Debugf("Denied reverse port forwarding request, please enable --reverse")
			failed(s.Errorf("Reverse port forwaring not enabled on server"))
			return
		}
	}
	var takeoverVictims []*reverseSession
	if s.config.ReverseTakeover {
		takeoverVictims = s.takeoverReverseSessions(id, userName, serverInbound)
	}
	if len(takeoverVictims) > 0 {
		waitReverseSessions(takeoverVictims, settings.EnvDuration("REVERSE_TAKEOVER_TIMEOUT", 2*time.Second))
	}
	//confirm reverse tunnels are available after optional takeover
	if !reverseCanListen(serverInbound) {
		for _, r := range serverInbound {
			if !r.CanListen() {
				failed(s.Errorf("Server cannot listen on %s", r.String()))
				return
			}
		}
	}
	//successfuly validated config!
	r.Reply(true, nil)
	sessionCtx, sessionCancel := context.WithCancel(req.Context())
	defer sessionCancel()
	unregisterReverseSession := s.registerReverseSession(id, userName, sessionCancel, serverInbound)
	defer unregisterReverseSession()
	//tunnel per ssh connection
	tunnelConfig := tunnel.Config{
		Logger:           l,
		Inbound:          s.config.Reverse,
		Outbound:         true, //server always accepts outbound
		Socks:            s.config.Socks5,
		KeepAlive:        s.config.KeepAlive,
		KeepAliveTimeout: s.config.KeepAliveTimeout,
	}
	//enforce ACL on every channel, not just the initial config
	if user != nil {
		tunnelConfig.ACL = user.HasAccess
	}
	tunnel := tunnel.New(tunnelConfig)
	//bind
	eg, ctx := errgroup.WithContext(sessionCtx)
	eg.Go(func() error {
		//connected, handover ssh connection for tunnel to use, and block
		return tunnel.BindSSH(ctx, sshConn, reqs, chans)
	})
	eg.Go(func() error {
		//connected, setup reversed-remotes?
		if len(serverInbound) == 0 {
			return nil
		}
		//block
		return tunnel.BindRemotes(ctx, serverInbound)
	})
	err = eg.Wait()
	if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
		l.Debugf("Closed connection (%s)", err)
	} else {
		l.Debugf("Closed connection")
	}
}
