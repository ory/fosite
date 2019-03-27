// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ory/fosite (interfaces: TokenIntrospector)

// Package internal is a generated GoMock package.
package internal

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"

	fosite "github.com/ory/fosite"
)

// MockTokenIntrospector is a mock of TokenIntrospector interface
type MockTokenIntrospector struct {
	ctrl     *gomock.Controller
	recorder *MockTokenIntrospectorMockRecorder
}

// MockTokenIntrospectorMockRecorder is the mock recorder for MockTokenIntrospector
type MockTokenIntrospectorMockRecorder struct {
	mock *MockTokenIntrospector
}

// NewMockTokenIntrospector creates a new mock instance
func NewMockTokenIntrospector(ctrl *gomock.Controller) *MockTokenIntrospector {
	mock := &MockTokenIntrospector{ctrl: ctrl}
	mock.recorder = &MockTokenIntrospectorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockTokenIntrospector) EXPECT() *MockTokenIntrospectorMockRecorder {
	return m.recorder
}

// IntrospectToken mocks base method
func (m *MockTokenIntrospector) IntrospectToken(arg0 context.Context, arg1 string, arg2 fosite.TokenType, arg3 fosite.AccessRequester, arg4 []string) (fosite.TokenType, error) {
	ret := m.ctrl.Call(m, "IntrospectToken", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(fosite.TokenType)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IntrospectToken indicates an expected call of IntrospectToken
func (mr *MockTokenIntrospectorMockRecorder) IntrospectToken(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IntrospectToken", reflect.TypeOf((*MockTokenIntrospector)(nil).IntrospectToken), arg0, arg1, arg2, arg3, arg4)
}
