// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ory/fosite/handler/oauth2 (interfaces: AuthorizeCodeStrategy)

// Package internal is a generated GoMock package.
package internal

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	fosite "github.com/ory/fosite"
)

// MockAuthorizeCodeStrategy is a mock of AuthorizeCodeStrategy interface
type MockAuthorizeCodeStrategy struct {
	ctrl     *gomock.Controller
	recorder *MockAuthorizeCodeStrategyMockRecorder
}

// MockAuthorizeCodeStrategyMockRecorder is the mock recorder for MockAuthorizeCodeStrategy
type MockAuthorizeCodeStrategyMockRecorder struct {
	mock *MockAuthorizeCodeStrategy
}

// NewMockAuthorizeCodeStrategy creates a new mock instance
func NewMockAuthorizeCodeStrategy(ctrl *gomock.Controller) *MockAuthorizeCodeStrategy {
	mock := &MockAuthorizeCodeStrategy{ctrl: ctrl}
	mock.recorder = &MockAuthorizeCodeStrategyMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockAuthorizeCodeStrategy) EXPECT() *MockAuthorizeCodeStrategyMockRecorder {
	return m.recorder
}

// AuthorizeCodeSignature mocks base method
func (m *MockAuthorizeCodeStrategy) AuthorizeCodeSignature(arg0 string) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthorizeCodeSignature", arg0)
	ret0, _ := ret[0].(string)
	return ret0
}

// AuthorizeCodeSignature indicates an expected call of AuthorizeCodeSignature
func (mr *MockAuthorizeCodeStrategyMockRecorder) AuthorizeCodeSignature(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthorizeCodeSignature", reflect.TypeOf((*MockAuthorizeCodeStrategy)(nil).AuthorizeCodeSignature), arg0)
}

// GenerateAuthorizeCode mocks base method
func (m *MockAuthorizeCodeStrategy) GenerateAuthorizeCode(arg0 context.Context, arg1 fosite.Requester) (string, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateAuthorizeCode", arg0, arg1)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GenerateAuthorizeCode indicates an expected call of GenerateAuthorizeCode
func (mr *MockAuthorizeCodeStrategyMockRecorder) GenerateAuthorizeCode(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateAuthorizeCode", reflect.TypeOf((*MockAuthorizeCodeStrategy)(nil).GenerateAuthorizeCode), arg0, arg1)
}

// ValidateAuthorizeCode mocks base method
func (m *MockAuthorizeCodeStrategy) ValidateAuthorizeCode(arg0 context.Context, arg1 fosite.Requester, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateAuthorizeCode", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateAuthorizeCode indicates an expected call of ValidateAuthorizeCode
func (mr *MockAuthorizeCodeStrategyMockRecorder) ValidateAuthorizeCode(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateAuthorizeCode", reflect.TypeOf((*MockAuthorizeCodeStrategy)(nil).ValidateAuthorizeCode), arg0, arg1, arg2)
}
