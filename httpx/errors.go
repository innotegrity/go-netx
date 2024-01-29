package httpx

import (
	"fmt"

	"go.innotegrity.dev/errorx"
)

const (
	// Library error codes
	ProxyErrorCode    = 5100
	RequestErrorCode  = 5101
	ResponseErrorCode = 5102
)

type ProxyError struct {
	*errorx.BaseError

	// unexported fields
	msg string
}

func NewProxyError(msg string, err error) *ProxyError {
	return &ProxyError{
		BaseError: errorx.NewBaseError(ProxyErrorCode, err),
		msg:       msg,
	}
}

// Error returns the string version of the error.
func (e *ProxyError) Error() string {
	if e.InternalError() != nil {
		return fmt.Sprintf("%s: %s", e.msg, e.InternalError().Error())
	}
	return e.msg
}

func (e *ProxyError) Msg() string {
	return e.msg
}

type RequestError struct {
	*errorx.BaseError

	// unexported fields
	msg    string
	url    string
	method string
}

func NewRequestError(msg, url, method string, err error) *RequestError {
	return &RequestError{
		BaseError: errorx.NewBaseError(RequestErrorCode, err),
		msg:       msg,
		url:       url,
		method:    method,
	}
}

func (e *RequestError) Error() string {
	if e.InternalError() != nil {
		return fmt.Sprintf("%s: %s", e.msg, e.InternalError().Error())
	}
	return e.msg
}

func (e *RequestError) Method() string {
	return e.method
}

func (e *RequestError) Msg() string {
	return e.msg
}

func (e *RequestError) URL() string {
	return e.url
}

type ResponseError struct {
	*errorx.BaseError

	// unexported fields
	msg        string
	url        string
	method     string
	statusCode int
}

func NewResponseError(msg, url, method string, statusCode int, err error) *ResponseError {
	return &ResponseError{
		BaseError:  errorx.NewBaseError(ResponseErrorCode, err),
		msg:        msg,
		url:        url,
		method:     method,
		statusCode: statusCode,
	}
}

func (e *ResponseError) Error() string {
	if e.InternalError() != nil {
		return fmt.Sprintf("%s: %s", e.msg, e.InternalError().Error())
	}
	return e.msg
}

func (e *ResponseError) Method() string {
	return e.method
}

func (e *ResponseError) Msg() string {
	return e.msg
}

func (e *ResponseError) StatusCode() int {
	return e.statusCode
}

func (e *ResponseError) URL() string {
	return e.url
}
