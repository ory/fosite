// Automatically generated by MockGen. DO NOT EDIT!
// Source: github.com/ory/fosite (interfaces: TokenIntrospector)

package internal

import (
	gomock "github.com/golang/mock/gomock"
	fosite "github.com/ory/fosite"
	context "golang.org/x/net/context"
)

// Mock of TokenIntrospector interface
type MockTokenIntrospector struct {
	ctrl     *gomock.Controller
	recorder *_MockTokenIntrospectorRecorder
}

// Recorder for MockTokenIntrospector (not exported)
type _MockTokenIntrospectorRecorder struct {
	mock *MockTokenIntrospector
}

func NewMockTokenIntrospector(ctrl *gomock.Controller) *MockTokenIntrospector {
	mock := &MockTokenIntrospector{ctrl: ctrl}
	mock.recorder = &_MockTokenIntrospectorRecorder{mock}
	return mock
}

func (_m *MockTokenIntrospector) EXPECT() *_MockTokenIntrospectorRecorder {
	return _m.recorder
}

func (_m *MockTokenIntrospector) IntrospectToken(_param0 context.Context, _param1 string, _param2 fosite.TokenType, _param3 fosite.AccessRequester, _param4 []string) error {
	ret := _m.ctrl.Call(_m, "IntrospectToken", _param0, _param1, _param2, _param3, _param4)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockTokenIntrospectorRecorder) IntrospectToken(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "IntrospectToken", arg0, arg1, arg2, arg3, arg4)
}
