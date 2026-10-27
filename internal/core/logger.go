package core

import (
	"context"
	"sync"
)

type RequestAppInfo struct {
	mu       sync.Mutex
	ClientID string
	Name     string
}

type requestAppKey struct{}

func InitRequestApp(ctx context.Context, defaultClientID string) (context.Context, *RequestAppInfo) {
	info := &RequestAppInfo{ClientID: defaultClientID}
	return context.WithValue(ctx, requestAppKey{}, info), info
}

func SetRequestApp(ctx context.Context, clientID, name string) {
	if ctx == nil {
		return
	}
	info, ok := ctx.Value(requestAppKey{}).(*RequestAppInfo)
	if !ok || info == nil {
		return
	}
	info.mu.Lock()
	defer info.mu.Unlock()
	if clientID != "" {
		info.ClientID = clientID
	}
	if name != "" {
		info.Name = name
	}
}

func GetRequestApp(ctx context.Context) (clientID, name string) {
	if ctx == nil {
		return "", ""
	}
	info, ok := ctx.Value(requestAppKey{}).(*RequestAppInfo)
	if !ok || info == nil {
		return "", ""
	}
	info.mu.Lock()
	defer info.mu.Unlock()
	return info.ClientID, info.Name
}
