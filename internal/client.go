// Automatically generated by MockGen. DO NOT EDIT!
// Source: github.com/ory-am/fosite (interfaces: Client)

package internal

import (
	gomock "github.com/golang/mock/gomock"
	fosite "github.com/ory-am/fosite"
)

// Mock of Client interface
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *_MockClientRecorder
}

// Recorder for MockClient (not exported)
type _MockClientRecorder struct {
	mock *MockClient
}

func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &_MockClientRecorder{mock}
	return mock
}

func (_m *MockClient) EXPECT() *_MockClientRecorder {
	return _m.recorder
}

func (_m *MockClient) GetGrantTypes() fosite.Arguments {
	ret := _m.ctrl.Call(_m, "GetGrantTypes")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

func (_mr *_MockClientRecorder) GetGrantTypes() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetGrantTypes")
}

func (_m *MockClient) GetHashedSecret() []byte {
	ret := _m.ctrl.Call(_m, "GetHashedSecret")
	ret0, _ := ret[0].([]byte)
	return ret0
}

func (_mr *_MockClientRecorder) GetHashedSecret() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetHashedSecret")
}

func (_m *MockClient) GetID() string {
	ret := _m.ctrl.Call(_m, "GetID")
	ret0, _ := ret[0].(string)
	return ret0
}

func (_mr *_MockClientRecorder) GetID() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetID")
}

func (_m *MockClient) GetOwner() string {
	ret := _m.ctrl.Call(_m, "GetOwner")
	ret0, _ := ret[0].(string)
	return ret0
}

func (_mr *_MockClientRecorder) GetOwner() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetOwner")
}

func (_m *MockClient) GetRedirectURIs() []string {
	ret := _m.ctrl.Call(_m, "GetRedirectURIs")
	ret0, _ := ret[0].([]string)
	return ret0
}

func (_mr *_MockClientRecorder) GetRedirectURIs() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetRedirectURIs")
}

func (_m *MockClient) GetResponseTypes() fosite.Arguments {
	ret := _m.ctrl.Call(_m, "GetResponseTypes")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

func (_mr *_MockClientRecorder) GetResponseTypes() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetResponseTypes")
}
