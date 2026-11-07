package protocol

import "errors"

// Dispatcher executes a validated request and returns the response content
// nodes (see OKContent, BlockContent, ErrorContent). Returning a
// *ProtocolError produces that error code; any other error becomes
// internal_error.
type Dispatcher func(req *Request) ([]Node, error)

// HandleRequest is the agent's top-level entry point: authenticate, dispatch
// and sign, never failing. Every outcome is a signed response.
func HandleRequest(body, secret, hostname string, now int64, dispatch Dispatcher) string {
	var reqID *string
	version := PeekVersion(body)
	var content []Node

	req, err := ParseRequest(body, secret, hostname, now)
	if err == nil {
		reqID = req.ID
		version = req.Version
		content, err = dispatch(req)
	}
	if err != nil {
		var pe *ProtocolError
		if errors.As(err, &pe) {
			content = ErrorContent(pe.Code, pe.Message)
			if pe.ReqID != nil {
				reqID = pe.ReqID
			}
		} else {
			content = ErrorContent(InternalError, err.Error())
		}
	}
	params := ResponseParams{Secret: secret, Hostname: hostname, Version: version}
	if reqID != nil {
		params.ReqID = *reqID
	}
	out, signErr := SignResponse(content, params)
	if signErr != nil {
		// Unreachable: PeekVersion and ParseRequest only yield supported versions.
		panic(signErr)
	}
	return out
}
