package interfaces

import "net/http"

type VirtualHosterIdentifier interface {
	IsVirtualHostingRequest(req *http.Request) bool
}