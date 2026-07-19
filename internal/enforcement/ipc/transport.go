package ipc

import (
	"context"
	"errors"
	"net"
	"time"
)

const MaxExchangeTimeout = 2 * time.Second

var (
	ErrExchangeConfiguration = errors.New("executor IPC exchange configuration is invalid")
	ErrExchangeTransport     = errors.New("executor IPC exchange transport failed")
	ErrExchangeHandler       = errors.New("executor IPC exchange handler failed")
)

type Handler func(context.Context, []byte) ([]byte, error)

// ClientExchange owns conn for exactly one request and one response. It closes
// the write side after the request so the executor can reject any second or
// trailing request frame before invoking its privileged handler.
func ClientExchange(ctx context.Context, conn *net.UnixConn, request []byte, timeout time.Duration) ([]byte, error) {
	if ctx == nil || conn == nil || !validExchangeTimeout(timeout) {
		return nil, ErrExchangeConfiguration
	}
	defer conn.Close()
	exchangeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stopCancellation, err := armExchange(exchangeCtx, conn, timeout)
	if err != nil {
		return nil, err
	}
	defer stopCancellation()
	if err = WriteFrame(conn, request); err != nil {
		return nil, err
	}
	if err = conn.CloseWrite(); err != nil {
		return nil, ErrExchangeTransport
	}
	response, err := ReadSingleFrame(conn)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// ServerExchange owns conn for one request and response and invokes handler
// only after the request side has terminated cleanly. A panic is contained and
// closes the exchange without manufacturing a success response.
func ServerExchange(ctx context.Context, conn *net.UnixConn, timeout time.Duration, handler Handler) (err error) {
	if ctx == nil || conn == nil || handler == nil || !validExchangeTimeout(timeout) {
		if conn != nil {
			_ = conn.Close()
		}
		return ErrExchangeConfiguration
	}
	defer conn.Close()
	exchangeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = ErrExchangeHandler
		}
	}()
	stopCancellation, err := armExchange(exchangeCtx, conn, timeout)
	if err != nil {
		return err
	}
	defer stopCancellation()
	request, err := ReadSingleFrame(conn)
	if err != nil {
		return err
	}
	response, err := handler(exchangeCtx, request)
	if err != nil {
		return ErrExchangeHandler
	}
	if err = WriteFrame(conn, response); err != nil {
		return err
	}
	if err = conn.CloseWrite(); err != nil {
		return ErrExchangeTransport
	}
	return nil
}

func armExchange(ctx context.Context, conn *net.UnixConn, timeout time.Duration) (func() bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, ErrExchangeTransport
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	return stop, nil
}

func validExchangeTimeout(timeout time.Duration) bool {
	return timeout > 0 && timeout <= MaxExchangeTimeout
}
