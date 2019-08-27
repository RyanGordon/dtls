package udp

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const receiveMTU = 8192
const closeRecheckDuration = 100 * time.Millisecond

var errClosedListener = errors.New("udp: listener closed")

// Listener augments a connection-oriented Listener over a UDP PacketConn
type Listener struct {
	pConn *net.UDPConn

	lock      sync.RWMutex
	accepting bool
	acceptCh  chan *Conn
	doneCh    chan struct{}
	doneOnce  sync.Once

	conns map[string]*Conn
}

// Accept waits for and returns the next connection to the listener.
// You have to either close or read on all connection that are created.
func (l *Listener) Accept() (*Conn, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil

	case <-l.doneCh:
		return nil, errClosedListener
	}
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *Listener) Close(timeout time.Duration) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	var err error
	l.doneOnce.Do(func() {
		close(l.doneCh)
		err = l.closeConn(timeout)
	})

	return err
}

// closeConn gracefully waits for clients to close, up to the given
// timeout.
// The caller should hold the read lock.
func (l *Listener) closeConn(timeout time.Duration) error {
	if len(l.conns) == 0 {
		return l.pConn.Close()
	}

	timeoutTimer := time.NewTimer(timeout)

	for {
		select {
		case <-timeoutTimer.C:
			return l.pConn.Close()
		case <-time.After(closeRecheckDuration):
			if len(l.conns) == 0 {
				return l.pConn.Close()
			}
		}
	}
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.pConn.LocalAddr()
}

// Listen creates a new listener
func Listen(network string, laddr *net.UDPAddr) (*Listener, error) {
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		pConn:    conn,
		acceptCh: make(chan *Conn),
		conns:    make(map[string]*Conn),
		doneCh:   make(chan struct{}),
	}

	go l.readLoop()

	return l, nil
}

// readLoop has to tasks:
// 1. Dispatching incoming packets to the correct Conn.
//    It can therefore not be ended until all Conns are closed.
// 2. Creating a new Conn when receiving from a new remote.
func (l *Listener) readLoop() {
	buf := make([]byte, receiveMTU)

readLoop:
	for {
		n, raddr, err := l.pConn.ReadFrom(buf)
		if err != nil {
			return
		}
		conn, err := l.getConn(raddr)
		if err != nil {
			continue
		}
		select {
		case cBuf := <-conn.readCh:
			n = copy(cBuf, buf[:n])
			conn.sizeCh <- n
		case <-conn.doneCh:
			continue readLoop
		}
	}
}

func (l *Listener) getConn(raddr net.Addr) (*Conn, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	conn, ok := l.conns[raddr.String()]
	if !ok {
		if !l.accepting {
			return nil, errClosedListener
		}
		conn = l.newConn(raddr)
		l.conns[raddr.String()] = conn
		l.acceptCh <- conn
	}
	return conn, nil
}

// Conn augments a connection-oriented connection over a UDP PacketConn
type Conn struct {
	listener *Listener

	rAddr net.Addr

	readCh chan []byte
	sizeCh chan int

	lock     sync.RWMutex
	doneCh   chan struct{}
	doneOnce sync.Once
}

func (l *Listener) newConn(rAddr net.Addr) *Conn {
	return &Conn{
		listener: l,
		rAddr:    rAddr,
		readCh:   make(chan []byte),
		sizeCh:   make(chan int),
		doneCh:   make(chan struct{}),
	}
}

// Read
func (c *Conn) Read(p []byte) (int, error) {
	select {
	case c.readCh <- p:
		n := <-c.sizeCh
		return n, nil
	case <-c.doneCh:
		return 0, io.EOF
	}
}

// Write writes len(p) bytes from p to the DTLS connection
func (c *Conn) Write(p []byte) (n int, err error) {
	c.lock.Lock()
	l := c.listener
	c.lock.Unlock()

	if l == nil {
		return 0, io.EOF
	}

	return l.pConn.WriteTo(p, c.rAddr)
}

// Close closes the conn and releases any Read calls
func (c *Conn) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	var err error
	c.doneOnce.Do(func() {
		close(c.doneCh)
		c.listener.lock.Lock()
		delete(c.listener.conns, c.rAddr.String())
		c.listener.lock.Unlock()
		c.listener = nil
	})

	return err
}

// LocalAddr is a stub
func (c *Conn) LocalAddr() net.Addr {
	c.lock.Lock()
	l := c.listener
	c.lock.Unlock()

	if l == nil {
		return nil
	}

	return l.pConn.LocalAddr()
}

// RemoteAddr is a stub
func (c *Conn) RemoteAddr() net.Addr {
	return c.rAddr
}

// SetDeadline is a stub
func (c *Conn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline is a stub
func (c *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline is a stub
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return nil
}
