/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/updater"

	"github.com/Microsoft/go-winio"
	"github.com/sourcegraph/jsonrpc2"
)

type peerDto struct {
	PublicKey  string   `json:"publicKey"`
	AllowedIPs []string `json:"allowedIPs"`
	Endpoint   string   `json:"endpoint"`
}

type rpcHandler struct {
	wrap *ManagerService
}

func mapAddresses(strings []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(strings))
	for _, s := range strings {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

func mapPeers(dto []peerDto) ([]conf.Peer, error) {
	result := make([]conf.Peer, 0, len(dto))
	for _, s := range dto {
		allowedIPs, parseAllowedIPsErr := parseAllowedIPs(s.AllowedIPs)
		if parseAllowedIPsErr != nil {
			return nil, parseAllowedIPsErr
		}

		endpoint, parseEndpointErr := parseEndpoint(s.Endpoint)
		if parseEndpointErr != nil {
			return nil, parseEndpointErr
		}

		publicKeyBytes, parsePublicKeyErr := base64.StdEncoding.DecodeString(s.PublicKey)
		if parsePublicKeyErr != nil {
			return nil, parsePublicKeyErr
		}
		var publicKey conf.Key
		copy(publicKey[:], publicKeyBytes)

		result = append(result, conf.Peer{
			PublicKey:  publicKey,
			AllowedIPs: allowedIPs,
			Endpoint:   endpoint,
		})
	}
	return result, nil
}

func parseAllowedIPs(ips []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, len(ips))

	for i, ip := range ips {
		prefix, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, err
		}
		prefixes[i] = prefix
	}

	return prefixes, nil
}

func parseEndpoint(s string) (conf.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return conf.Endpoint{}, err
	}

	return conf.Endpoint{
		Host: addr.Addr().String(),
		Port: addr.Port(),
	}, nil
}

func (self *rpcHandler) Handle(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
	//
	{
		var paramsStr string
		if req.Params != nil {
			paramsStr = string(*req.Params)
		} else {
			paramsStr = "null"
		}
		if req.Notif {
			log.Printf("Отримано нотифікацію: метод=%s, параметри=%s", req.Method, paramsStr)
			return // Згідно зі специфікацією JSON-RPC 2.0, відповідь не надсилається
		} else {
			log.Printf("Отримано RPC call: метод=%s, параметри=%s", req.Method, paramsStr)
		}
	}

	switch req.Method {
	case "create":
		var params struct {
			TunnelName string    `json:"tunnelName"`
			ListenPort uint16    `json:"listenPort"`
			PrivateKey string    `json:"privateKey"`
			Addresses  []string  `json:"addresses"`
			Peers      []peerDto `json:"peers"`
		}
		if err := json.Unmarshal(*req.Params, &params); err != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInvalidParams, Message: err.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}
		addresses, err := mapAddresses(params.Addresses)
		if err != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInvalidParams, Message: err.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}
		peers, parsePeersErr := mapPeers(params.Peers)
		if parsePeersErr != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInvalidParams, Message: parsePeersErr.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}

		privateKeyBytes, parsePrivateKeyErr := base64.StdEncoding.DecodeString(params.PrivateKey)
		if parsePrivateKeyErr != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInvalidParams, Message: parsePrivateKeyErr.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}
		var privateKey conf.Key
		copy(privateKey[:], privateKeyBytes)

		tunnelConfig := conf.Config{
			Name: params.TunnelName,
			Interface: conf.Interface{
				PrivateKey: privateKey,
				ListenPort: params.ListenPort,
				Addresses:  addresses,
			},
			Peers: peers,
		}

		if _, retErr := self.wrap.Create(&tunnelConfig); retErr != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInternalError, Message: retErr.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}

		if err := conn.Reply(ctx, req.ID, nil); err != nil {
			log.Printf("Failed to JSON-RPC reply: %v", err)
			return
		}
	case "start":
		var params struct {
			TunnelName string `json:"tunnelName"`
		}
		if err := json.Unmarshal(*req.Params, &params); err != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInvalidParams, Message: err.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}
		if retErr := self.wrap.Start(params.TunnelName); retErr != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInternalError, Message: retErr.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}
		if err := conn.Reply(ctx, req.ID, nil); err != nil {
			log.Printf("Failed to JSON-RPC reply: %v", err)
			return
		}
	case "stop":
		var params struct {
			TunnelName string `json:"tunnelName"`
		}
		if err := json.Unmarshal(*req.Params, &params); err != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInvalidParams, Message: err.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}
		if retErr := self.wrap.WaitForStop(params.TunnelName); retErr != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInternalError, Message: retErr.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}
		if err := conn.Reply(ctx, req.ID, nil); err != nil {
			log.Printf("Failed to JSON-RPC reply: %v", err)
			return
		}
	case "delete":
		var params struct {
			TunnelName string `json:"tunnelName"`
		}
		if err := json.Unmarshal(*req.Params, &params); err != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInvalidParams, Message: err.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}
		if retErr := self.wrap.Delete(params.TunnelName); retErr != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInternalError, Message: retErr.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}
		if err := conn.Reply(ctx, req.ID, nil); err != nil {
			log.Printf("Failed to JSON-RPC reply: %v", err)
			return
		}
	case "list":
		names, err := conf.ListConfigNames()
		if err != nil {
			errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeInternalError, Message: err.Error()}
			conn.ReplyWithError(ctx, req.ID, errObj)
			return
		}
		if err := conn.Reply(ctx, req.ID, names); err != nil {
			log.Printf("Failed to JSON-RPC reply: %v", err)
			return
		}
	default:
		errObj := &jsonrpc2.Error{Code: jsonrpc2.CodeMethodNotFound, Message: "Method not found"}
		conn.ReplyWithError(ctx, req.ID, errObj)
	}
}

var (
	managerServices     = make(map[*ManagerService]bool)
	managerServicesLock sync.RWMutex
	haveQuit            uint32
	quitManagersChan    = make(chan struct{}, 1)
)

type ManagerService struct {
	events        *os.File
	eventLock     sync.Mutex
	elevatedToken windows.Token
}

func (s *ManagerService) StoredConfig(tunnelName string) (*conf.Config, error) {
	conf, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return nil, err
	}
	if s.elevatedToken == 0 {
		conf.Redact()
	}
	return conf, nil
}

func (s *ManagerService) RuntimeConfig(tunnelName string) (*conf.Config, error) {
	storedConfig, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return nil, err
	}
	driverAdapter, err := findDriverAdapter(tunnelName)
	if err != nil {
		return nil, err
	}
	runtimeConfig, err := driverAdapter.Configuration()
	if err != nil {
		driverAdapter.Unlock()
		releaseDriverAdapter(tunnelName)
		return nil, err
	}
	conf := conf.FromDriverConfiguration(runtimeConfig, storedConfig)
	driverAdapter.Unlock()
	if s.elevatedToken == 0 {
		conf.Redact()
	}
	return conf, nil
}

func (s *ManagerService) Start(tunnelName string) error {
	c, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return err
	}

	// Figure out which tunnels have intersecting addresses/routes and stop those.
	trackedTunnelsLock.Lock()
	tt := make([]string, 0, len(trackedTunnels))
	var inTransition string
	for t, state := range trackedTunnels {
		c2, err := conf.LoadFromName(t)
		if err != nil || !c.IntersectsWith(c2) {
			// If we can't get the config, assume it doesn't intersect.
			continue
		}
		tt = append(tt, t)
		if len(t) > 0 && (state == TunnelStarting || state == TunnelUnknown) {
			inTransition = t
			break
		}
	}
	trackedTunnelsLock.Unlock()
	if len(inTransition) != 0 {
		return fmt.Errorf("Please allow the tunnel ‘%s’ to finish activating", inTransition)
	}

	// Stop those intersecting tunnels asynchronously.
	go func() {
		for _, t := range tt {
			s.Stop(t)
		}
		for _, t := range tt {
			state, err := s.State(t)
			if err == nil && (state == TunnelStarted || state == TunnelStarting) {
				log.Printf("[%s] Trying again to stop zombie tunnel", t)
				s.Stop(t)
				time.Sleep(time.Millisecond * 100)
			}
		}
	}()
	// After the stop process has begun, but before it's finished, we install the new one.
	path, err := c.Path()
	if err != nil {
		return err
	}
	return InstallTunnel(path)
}

func (s *ManagerService) Stop(tunnelName string) error {
	err := UninstallTunnel(tunnelName)
	if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		_, notExistsError := conf.LoadFromName(tunnelName)
		if notExistsError == nil {
			return nil
		}
	}
	return err
}

func (s *ManagerService) WaitForStop(tunnelName string) error {
	serviceName, err := conf.ServiceNameOfTunnel(tunnelName)
	if err != nil {
		return err
	}
	m, err := serviceManager()
	if err != nil {
		return err
	}
	for {
		service, err := m.OpenService(serviceName)
		if err == nil || err == windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			if err == nil {
				service.Close()
			}
			time.Sleep(time.Second / 3)
		} else {
			return nil
		}
	}
}

func (s *ManagerService) Delete(tunnelName string) error {
	if s.elevatedToken == 0 {
		return windows.ERROR_ACCESS_DENIED
	}
	err := s.Stop(tunnelName)
	if err != nil {
		return err
	}
	return conf.DeleteName(tunnelName)
}

func (s *ManagerService) State(tunnelName string) (TunnelState, error) {
	serviceName, err := conf.ServiceNameOfTunnel(tunnelName)
	if err != nil {
		return 0, err
	}
	m, err := serviceManager()
	if err != nil {
		return 0, err
	}
	service, err := m.OpenService(serviceName)
	if err != nil {
		return TunnelStopped, nil
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return TunnelUnknown, nil
	}
	switch status.State {
	case svc.Stopped:
		return TunnelStopped, nil
	case svc.StopPending:
		return TunnelStopping, nil
	case svc.Running:
		return TunnelStarted, nil
	case svc.StartPending:
		return TunnelStarting, nil
	default:
		return TunnelUnknown, nil
	}
}

func (s *ManagerService) GlobalState() TunnelState {
	return trackedTunnelsGlobalState()
}

func (s *ManagerService) Create(tunnelConfig *conf.Config) (*Tunnel, error) {
	if s.elevatedToken == 0 {
		return nil, windows.ERROR_ACCESS_DENIED
	}
	err := tunnelConfig.Save(true)
	if err != nil {
		return nil, err
	}
	return &Tunnel{tunnelConfig.Name}, nil
	// TODO: handle already existing situation
	// TODO: handle already running and existing situation
}

func (s *ManagerService) Tunnels() ([]Tunnel, error) {
	names, err := conf.ListConfigNames()
	if err != nil {
		return nil, err
	}
	tunnels := make([]Tunnel, len(names))
	for i := range tunnels {
		tunnels[i].Name = names[i]
	}
	return tunnels, nil
	// TODO: account for running ones that aren't in the configuration store somehow
}

func (s *ManagerService) Quit(stopTunnelsOnQuit bool) (alreadyQuit bool, err error) {
	if s.elevatedToken == 0 {
		return false, windows.ERROR_ACCESS_DENIED
	}
	if !atomic.CompareAndSwapUint32(&haveQuit, 0, 1) {
		return true, nil
	}

	// Work around potential race condition of delivering messages to the wrong process by removing from notifications.
	managerServicesLock.Lock()
	s.eventLock.Lock()
	s.events = nil
	s.eventLock.Unlock()
	delete(managerServices, s)
	managerServicesLock.Unlock()

	if stopTunnelsOnQuit {
		names, err := conf.ListConfigNames()
		if err != nil {
			return false, err
		}
		for _, name := range names {
			UninstallTunnel(name)
		}
	}

	quitManagersChan <- struct{}{}
	return false, nil
}

func (s *ManagerService) UpdateState() UpdateState {
	return updateState
}

func (s *ManagerService) Update() {
	if s.elevatedToken == 0 {
		return
	}
	progress := updater.DownloadVerifyAndExecute(uintptr(s.elevatedToken))
	go func() {
		for {
			dp := <-progress
			IPCServerNotifyUpdateProgress(dp)
			if dp.Complete || dp.Error != nil {
				return
			}
		}
	}()
}

func (s *ManagerService) ServeConn(reader io.Reader, writer io.Writer) {
	decoder := gob.NewDecoder(reader)
	encoder := gob.NewEncoder(writer)
	for {
		var methodType MethodType
		err := decoder.Decode(&methodType)
		if err != nil {
			return
		}
		switch methodType {
		case StoredConfigMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			config, retErr := s.StoredConfig(tunnelName)
			if config == nil {
				config = &conf.Config{}
			}
			err = encoder.Encode(*config)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case RuntimeConfigMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			config, retErr := s.RuntimeConfig(tunnelName)
			if config == nil {
				config = &conf.Config{}
			}
			err = encoder.Encode(*config)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StartMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.Start(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StopMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.Stop(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case WaitForStopMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.WaitForStop(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case DeleteMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.Delete(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StateMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			state, retErr := s.State(tunnelName)
			err = encoder.Encode(state)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case GlobalStateMethodType:
			state := s.GlobalState()
			err = encoder.Encode(state)
			if err != nil {
				return
			}
		case CreateMethodType:
			var config conf.Config
			err := decoder.Decode(&config)
			if err != nil {
				return
			}
			tunnel, retErr := s.Create(&config)
			if tunnel == nil {
				tunnel = &Tunnel{}
			}
			err = encoder.Encode(tunnel)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case TunnelsMethodType:
			tunnels, retErr := s.Tunnels()
			err = encoder.Encode(tunnels)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case QuitMethodType:
			var stopTunnelsOnQuit bool
			err := decoder.Decode(&stopTunnelsOnQuit)
			if err != nil {
				return
			}
			alreadyQuit, retErr := s.Quit(stopTunnelsOnQuit)
			err = encoder.Encode(alreadyQuit)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case UpdateStateMethodType:
			updateState := s.UpdateState()
			err = encoder.Encode(updateState)
			if err != nil {
				return
			}
		case UpdateMethodType:
			s.Update()
		default:
			return
		}
	}
}

func IPCServerListen(reader, writer, events *os.File, elevatedToken windows.Token) {
	service := &ManagerService{
		events:        events,
		elevatedToken: elevatedToken,
	}

	go func() {
		managerServicesLock.Lock()
		managerServices[service] = true
		managerServicesLock.Unlock()
		runtimeCtx, runtimeCancel := context.WithCancel(context.Background())

		go func(ctx context.Context, service *ManagerService) {
			pipePath := `\\.\pipe\graicc\wiregurd-manager-jsonrpc`

			config := &winio.PipeConfig{
				MessageMode:      true, // Вмикає режим повідомлень (PIPE_TYPE_MESSAGE / PIPE_READMODE_MESSAGE)
				InputBufferSize:  4096,
				OutputBufferSize: 4096,
				// Цей рядок є записом у форматі SDDL (Security Descriptor Definition Language), який визначає права доступу до Named Pipe в ОС Windows.s
				// Цей рядок надає повний доступ до Named Pipe для будь-якого процесу чи користувача в системі.
				SecurityDescriptor: "D:P(A;;GA;;;WD)",
			}

			listener, err := winio.ListenPipe(pipePath, config)
			if err != nil {
				log.Printf("Помилка запуску JSON-RPC сервера: %v", err)
				return
			}

			go func() {
				<-ctx.Done()
				listener.Close()
			}()

			for {
				conn, err := listener.Accept()
				if err != nil {
					// Перевірка, чи закриття викликане скасуванням контексту
					if errors.Is(err, net.ErrClosed) {
						log.Println("JSON-RPC сервер зупинено через скасування контексту")
						return
					}
					log.Printf("Помилка accept у JSON-RPC сервері: %v", err)
					continue
				}
				log.Printf("JSON-RPC client connection opened")

				go func(conn net.Conn) {
					defer conn.Close()

					jsonrpc2ObjectStream := jsonrpc2.NewPlainObjectStream(conn)
					defer jsonrpc2ObjectStream.Close()

					jsonrpc2Conn := jsonrpc2.NewConn(ctx, jsonrpc2ObjectStream, &rpcHandler{
						wrap: service,
					})
					defer jsonrpc2Conn.Close()

					ticker := time.NewTicker(2 * time.Hour)
					defer ticker.Stop()

					for {
						select {
						case <-ticker.C:
							notificationParams := map[string]string{"status": "periodic_update"}
							err := jsonrpc2Conn.Notify(ctx, "server_notification", notificationParams)
							if err != nil {
								log.Printf("Помилка відправки нотифікації (можливо клієнт відключився): %v", err)
								return
							}
							// conn.Write([]byte("Hello\n"))
						case <-ctx.Done():
							log.Printf("JSON-RPC client connection close")
							return
						}
					}
				}(conn)
			}
		}(runtimeCtx, service)

		service.ServeConn(reader, writer)
		runtimeCancel()
		managerServicesLock.Lock()
		service.eventLock.Lock()
		service.events = nil
		service.eventLock.Unlock()
		delete(managerServices, service)
		managerServicesLock.Unlock()
	}()
}

func notifyAll(notificationType NotificationType, adminOnly bool, ifaces ...any) {
	if len(managerServices) == 0 {
		return
	}

	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(notificationType)
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		err = encoder.Encode(iface)
		if err != nil {
			return
		}
	}

	managerServicesLock.RLock()
	for m := range managerServices {
		if m.elevatedToken == 0 && adminOnly {
			continue
		}
		go func(m *ManagerService) {
			m.eventLock.Lock()
			defer m.eventLock.Unlock()
			if m.events != nil {
				m.events.SetWriteDeadline(time.Now().Add(time.Second))
				m.events.Write(buf.Bytes())
			}
		}(m)
	}
	managerServicesLock.RUnlock()
}

func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func IPCServerNotifyTunnelChange(name string, state TunnelState, err error) {
	notifyAll(TunnelChangeNotificationType, false, name, state, trackedTunnelsGlobalState(), errToString(err))
}

func IPCServerNotifyTunnelsChange() {
	notifyAll(TunnelsChangeNotificationType, false)
}

func IPCServerNotifyUpdateFound(state UpdateState) {
	notifyAll(UpdateFoundNotificationType, false, state)
}

func IPCServerNotifyUpdateProgress(dp updater.DownloadProgress) {
	notifyAll(UpdateProgressNotificationType, true, dp.Activity, dp.BytesDownloaded, dp.BytesTotal, errToString(dp.Error), dp.Complete)
}

func IPCServerNotifyManagerStopping() {
	notifyAll(ManagerStoppingNotificationType, false)
	time.Sleep(time.Millisecond * 200)
}
