package mock

import mock "github.com/stretchr/testify/mock"

// BlobCodec is an autogenerated mock type for the BlobCodec type
type BlobCodec struct {
	mock.Mock
}

// DecodeBlob provides a mock function with given fields: encodedData
func (_m *BlobCodec) DecodeBlob(encodedData []byte) ([]byte, error) {
	ret := _m.Called(encodedData)

	if len(ret) == 0 {
		panic("no return value specified for DecodeBlob")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte) ([]byte, error)); ok {
		return rf(encodedData)
	}
	if rf, ok := ret.Get(0).(func([]byte) []byte); ok {
		r0 = rf(encodedData)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(encodedData)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// EncodeBlob provides a mock function with given fields: rawData
func (_m *BlobCodec) EncodeBlob(rawData []byte) ([]byte, error) {
	ret := _m.Called(rawData)

	if len(ret) == 0 {
		panic("no return value specified for EncodeBlob")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte) ([]byte, error)); ok {
		return rf(rawData)
	}
	if rf, ok := ret.Get(0).(func([]byte) []byte); ok {
		r0 = rf(rawData)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(rawData)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}