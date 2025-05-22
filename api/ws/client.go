package ws

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cocoyes/okex"
	"github.com/cocoyes/okex/events"
	"github.com/go-logr/logr"
	"github.com/gorilla/websocket"
)

const (
	redialTick = 2 * time.Second
	writeWait  = 3 * time.Second
	pongWait   = 25 * time.Second
	PingPeriod = 15 * time.Second
)

type ClientWs struct {
	url           map[bool]okex.BaseURL
	apiKey        string
	secretKey     []byte
	passphrase    string
	conn          map[bool]*websocket.Conn
	mu            map[bool]*sync.RWMutex
	ctx           context.Context
	Cancel        context.CancelFunc
	DoneChan      chan interface{}
	ErrChan       chan *events.Error
	SubscribeChan chan *events.Subscribe
	UnsubscribeCh chan *events.Unsubscribe
	LoginChan     chan *events.Login
	SuccessChan   chan *events.Success
	sendChan      map[bool]chan []byte
	lastTransmit  map[bool]*time.Time
	AuthRequested *time.Time
	Authorized    bool
	Private       *Private
	Public        *Public
	Trade         *Trade
	log           logr.Logger
	lock          sync.RWMutex // 一把大锁保护所有 map
}

type ClientOption func(c *ClientWs)

func NewClient(ctx context.Context, apiKey, secretKey, passphrase string, url map[bool]okex.BaseURL, opts ...ClientOption) *ClientWs {
	ctx, cancel := context.WithCancel(ctx)
	c := &ClientWs{
		url:          url,
		apiKey:       apiKey,
		secretKey:    []byte(secretKey),
		passphrase:   passphrase,
		conn:         make(map[bool]*websocket.Conn),
		mu:           map[bool]*sync.RWMutex{true: {}, false: {}},
		ctx:          ctx,
		Cancel:       cancel,
		sendChan:     map[bool]chan []byte{true: make(chan []byte, 3), false: make(chan []byte, 3)},
		DoneChan:     make(chan interface{}, 32),
		lastTransmit: make(map[bool]*time.Time),
		log:          logr.New(nil),
	}

	c.Private = NewPrivate(c)
	c.Public = NewPublic(c)
	c.Trade = NewTrade(c)

	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *ClientWs) Connect(p bool) error {
	c.lock.RLock()
	conn := c.conn[p]
	c.lock.RUnlock()
	if conn != nil {
		return nil
	}
	return c.dialRetry(p)
}

func (c *ClientWs) dialRetry(p bool) error {
	err := c.dial(p)
	if err == nil {
		return nil
	}
	c.log.Error(err, "failed to dial ws connection")
	ticker := time.NewTicker(redialTick)
	defer ticker.Stop()
	counter := 0
	for {
		select {
		case <-ticker.C:
			err = c.dial(p)
			if err == nil {
				return nil
			}
			counter++
			c.log.Error(err, "failed to dial ws connection", "attempt", counter)
		case <-c.ctx.Done():
			return c.handleCancel("connect")
		}
	}
}

func (c *ClientWs) CheckConnect(p bool) bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.conn[p] != nil
}

func (c *ClientWs) Login() error {
	c.lock.RLock()
	authorized := c.Authorized
	c.lock.RUnlock()
	if authorized {
		return nil
	}

	c.lock.RLock()
	ar := c.AuthRequested
	c.lock.RUnlock()
	if ar != nil && time.Since(*ar).Seconds() < 30 {
		return nil
	}

	now := time.Now()
	c.lock.Lock()
	c.AuthRequested = &now
	c.lock.Unlock()
	method := http.MethodGet
	path := "/users/self/verify"
	ts, sign := c.sign(method, path)
	args := []map[string]string{
		{
			"apiKey":     c.apiKey,
			"passphrase": c.passphrase,
			"timestamp":  ts,
			"sign":       sign,
		},
	}

	return c.Send(true, okex.LoginOperation, args)
}

func (c *ClientWs) Subscribe(p bool, ch []okex.ChannelName, args map[string]string) error {
	count := 1
	if len(ch) != 0 {
		count = len(ch)
	}

	tmpArgs := make([]map[string]string, count)
	tmpArgs[0] = args

	for i, name := range ch {
		tmpArgs[i] = map[string]string{}
		tmpArgs[i]["channel"] = string(name)
		for k, v := range args {
			tmpArgs[i][k] = v
		}
	}

	return c.Send(p, okex.SubscribeOperation, tmpArgs)
}

func (c *ClientWs) Unsubscribe(p bool, ch []okex.ChannelName, args map[string]string) error {
	tmpArgs := make([]map[string]string, len(ch))
	for i, name := range ch {
		tmpArgs[i] = make(map[string]string)
		tmpArgs[i]["channel"] = string(name)
		for k, v := range args {
			tmpArgs[i][k] = v
		}
	}

	return c.Send(p, okex.UnsubscribeOperation, tmpArgs)
}

func (c *ClientWs) Send(p bool, op okex.Operation, args []map[string]string, extras ...map[string]string) error {
	if op != okex.LoginOperation {
		err := c.Connect(p)
		if err == nil {
			if p {
				err = c.WaitForAuthorization()
				if err != nil {
					return err
				}
			}
		} else {
			return err
		}
	}

	data := map[string]interface{}{
		"op":   op,
		"args": args,
	}

	for _, extra := range extras {
		for k, v := range extra {
			data[k] = v
		}
	}

	j, err := json.Marshal(data)
	if err != nil {
		return err
	}

	c.lock.RLock()
	ch := c.sendChan[p]
	c.lock.RUnlock()
	if ch == nil {
		return errors.New("sendChan is nil")
	}
	ch <- j

	return nil
}

func (c *ClientWs) SetChannels(errCh chan *events.Error, subCh chan *events.Subscribe, unSub chan *events.Unsubscribe, lCh chan *events.Login, sCh chan *events.Success) {
	c.ErrChan = errCh
	c.SubscribeChan = subCh
	c.UnsubscribeCh = unSub
	c.LoginChan = lCh
	c.SuccessChan = sCh
}

func (c *ClientWs) WaitForAuthorization() error {
	c.lock.RLock()
	if c.Authorized {
		c.lock.RUnlock()
		return nil
	}
	c.lock.RUnlock()

	if err := c.Login(); err != nil {
		return err
	}

	ticker := time.NewTicker(time.Millisecond * 300)
	defer ticker.Stop()

	for range ticker.C {
		c.lock.RLock()
		ok := c.Authorized
		c.lock.RUnlock()
		if ok {
			return nil
		}
	}

	return nil
}

func (c *ClientWs) dial(p bool) error {
	c.lock.Lock()
	if c.conn == nil {
		c.conn = make(map[bool]*websocket.Conn)
	}
	if c.sendChan == nil {
		c.sendChan = make(map[bool]chan []byte)
	}
	if c.lastTransmit == nil {
		c.lastTransmit = make(map[bool]*time.Time)
	}
	if _, ok := c.sendChan[p]; !ok || c.sendChan[p] == nil {
		c.sendChan[p] = make(chan []byte, 3)
	}
	c.lock.Unlock()

	// p维度锁
	if c.mu == nil {
		c.mu = make(map[bool]*sync.RWMutex)
	}
	if c.mu[p] == nil {
		c.mu[p] = &sync.RWMutex{}
	}
	c.mu[p].Lock()
	conn, res, err := websocket.DefaultDialer.Dial(string(c.url[p]), nil)
	if err != nil {
		statusCode := 0
		if res != nil {
			statusCode = res.StatusCode
		}
		c.mu[p].Unlock()
		return fmt.Errorf("error %d: %w", statusCode, err)
	}
	defer res.Body.Close()

	c.lock.Lock()
	c.conn[p] = conn
	c.lock.Unlock()
	c.mu[p].Unlock()

	go func() {
		defer func() {
			c.Cancel()
			c.mu[p].Lock()
			c.lock.Lock()
			if c.conn[p] != nil {
				c.conn[p].Close()
				delete(c.conn, p)
			}
			if c.sendChan[p] != nil {
				close(c.sendChan[p])
				delete(c.sendChan, p)
			}
			delete(c.lastTransmit, p)
			c.lock.Unlock()
			c.mu[p].Unlock()
		}()
		if err := c.receiver(p); err != nil {
			if !strings.Contains(err.Error(), "operation cancelled: receiver") {
				c.ErrChan <- &events.Error{Event: "error", Msg: err.Error()}
			}
			c.log.Error(err, "receiver error")
		}
	}()

	go func() {
		defer func() {
			c.Cancel()
			c.mu[p].Lock()
			c.lock.Lock()
			if c.conn[p] != nil {
				c.conn[p].Close()
				delete(c.conn, p)
			}
			if c.sendChan[p] != nil {
				close(c.sendChan[p])
				delete(c.sendChan, p)
			}
			delete(c.lastTransmit, p)
			c.lock.Unlock()
			c.mu[p].Unlock()
		}()
		if err := c.sender(p); err != nil {
			if !strings.Contains(err.Error(), "operation cancelled: sender") {
				c.ErrChan <- &events.Error{Event: "error", Msg: err.Error()}
			}
			c.log.Error(err, "sender error")
		}
	}()

	return nil
}

func (c *ClientWs) sender(p bool) error {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	for {
		c.lock.RLock()
		dataChan := c.sendChan[p]
		c.lock.RUnlock()
		if dataChan == nil {
			return errors.New("sendChan is nil")
		}

		select {
		case data := <-dataChan:
			c.lock.RLock()
			conn := c.conn[p]
			c.lock.RUnlock()
			if conn == nil {
				return errors.New("conn is nil")
			}
			err := conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err != nil {
				return err
			}
			w, err := conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return err
			}
			if _, err = w.Write(data); err != nil {
				return err
			}
			if err := w.Close(); err != nil {
				return err
			}
		case <-ticker.C:
			c.lock.RLock()
			conn := c.conn[p]
			last := c.lastTransmit[p]
			c.lock.RUnlock()
			if conn != nil && (last == nil || (last != nil && time.Since(*last) > PingPeriod)) {
				c.lock.RLock()
				dataChan := c.sendChan[p]
				c.lock.RUnlock()
				if dataChan != nil {
					select {
					case dataChan <- []byte("ping"):
					default:
					}
				}
			}
		case <-c.ctx.Done():
			return nil
		}
	}
}

func (c *ClientWs) receiver(p bool) error {
	for {
		select {
		case <-c.ctx.Done():
			return nil
		default:
			c.lock.RLock()
			conn := c.conn[p]
			c.lock.RUnlock()
			if conn == nil {
				return errors.New("conn is nil")
			}
			err := conn.SetReadDeadline(time.Now().Add(pongWait))
			if err != nil {
				return err
			}
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return err
			}
			now := time.Now()
			c.lock.Lock()
			c.lastTransmit[p] = &now
			c.lock.Unlock()
			if mt == websocket.TextMessage && string(data) != "pong" {
				e := &events.Basic{}
				if err := json.Unmarshal(data, e); err != nil {
					return err
				}
				go c.process(data, e)
			}
		}
	}
}

func (c *ClientWs) sign(method, path string) (string, string) {
	t := time.Now().UTC().Unix()
	ts := fmt.Sprint(t)
	s := ts + method + path
	p := []byte(s)
	h := hmac.New(sha256.New, c.secretKey)
	h.Write(p)

	return ts, base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (c *ClientWs) handleCancel(msg string) error {
	go func() {
		c.DoneChan <- msg
	}()
	return fmt.Errorf("operation cancelled: %s", msg)
}

func (c *ClientWs) process(data []byte, e *events.Basic) bool {
	switch e.Event {
	case "error":
		e := events.Error{}
		_ = json.Unmarshal(data, &e)
		go func() {
			if c.ErrChan != nil {
				c.ErrChan <- &e
			}
		}()
		return true
	case "subscribe":
		e := events.Subscribe{}
		_ = json.Unmarshal(data, &e)
		if c.SubscribeChan != nil {
			c.SubscribeChan <- &e
		}
		return true
	case "unsubscribe":
		e := events.Unsubscribe{}
		_ = json.Unmarshal(data, &e)
		go func() {
			if c.UnsubscribeCh != nil {
				c.UnsubscribeCh <- &e
			}
		}()
		return true
	case "login":
		c.lock.RLock()
		ar := c.AuthRequested
		c.lock.RUnlock()
		if ar != nil && time.Since(*ar).Seconds() > 30 {
			c.lock.Lock()
			c.AuthRequested = nil
			c.lock.Unlock()
			_ = c.Login()
			break
		}
		c.lock.Lock()
		c.Authorized = true
		c.lock.Unlock()
		e := events.Login{}
		_ = json.Unmarshal(data, &e)
		go func() {
			if c.LoginChan != nil {
				c.LoginChan <- &e
			}
		}()
		return true
	}
	if c.Private.Process(data, e) {
		return true
	}
	if c.Public.Process(data, e) {
		return true
	}
	if e.ID != "" {
		if e.Code != 0 {
			ee := *e
			ee.Event = "error"
			return c.process(data, &ee)
		}
		e := events.Success{}
		_ = json.Unmarshal(data, &e)
		if c.SuccessChan != nil {
			c.SuccessChan <- &e
		}
		return true
	}
	return false
}

func WithLogger(sink logr.LogSink) ClientOption {
	return func(c *ClientWs) {
		c.log = c.log.WithSink(sink)
	}
}
