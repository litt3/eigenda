// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v4.23.4
// source: node/v2/node_v2.proto

package v2

import (
	common "github.com/Layr-Labs/eigenda/api/grpc/common"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type StoreChunksRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// list of blob certificates to process
	BlobCertificates []*common.BlobCertificate `protobuf:"bytes,1,rep,name=blob_certificates,json=blobCertificates,proto3" json:"blob_certificates,omitempty"`
}

func (x *StoreChunksRequest) Reset() {
	*x = StoreChunksRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_v2_node_v2_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StoreChunksRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreChunksRequest) ProtoMessage() {}

func (x *StoreChunksRequest) ProtoReflect() protoreflect.Message {
	mi := &file_node_v2_node_v2_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreChunksRequest.ProtoReflect.Descriptor instead.
func (*StoreChunksRequest) Descriptor() ([]byte, []int) {
	return file_node_v2_node_v2_proto_rawDescGZIP(), []int{0}
}

func (x *StoreChunksRequest) GetBlobCertificates() []*common.BlobCertificate {
	if x != nil {
		return x.BlobCertificates
	}
	return nil
}

type StoreChunksReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Signatures []*wrapperspb.BytesValue `protobuf:"bytes,1,rep,name=signatures,proto3" json:"signatures,omitempty"`
}

func (x *StoreChunksReply) Reset() {
	*x = StoreChunksReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_v2_node_v2_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StoreChunksReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreChunksReply) ProtoMessage() {}

func (x *StoreChunksReply) ProtoReflect() protoreflect.Message {
	mi := &file_node_v2_node_v2_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreChunksReply.ProtoReflect.Descriptor instead.
func (*StoreChunksReply) Descriptor() ([]byte, []int) {
	return file_node_v2_node_v2_proto_rawDescGZIP(), []int{1}
}

func (x *StoreChunksReply) GetSignatures() []*wrapperspb.BytesValue {
	if x != nil {
		return x.Signatures
	}
	return nil
}

type GetChunksRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BlobKey []byte `protobuf:"bytes,1,opt,name=blob_key,json=blobKey,proto3" json:"blob_key,omitempty"`
	// Which quorum of the blob to retrieve for (note: a blob can have multiple
	// quorums and the chunks for different quorums at a Node can be different).
	// The ID must be in range [0, 254].
	QuorumId uint32 `protobuf:"varint,2,opt,name=quorum_id,json=quorumId,proto3" json:"quorum_id,omitempty"`
}

func (x *GetChunksRequest) Reset() {
	*x = GetChunksRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_v2_node_v2_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetChunksRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetChunksRequest) ProtoMessage() {}

func (x *GetChunksRequest) ProtoReflect() protoreflect.Message {
	mi := &file_node_v2_node_v2_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetChunksRequest.ProtoReflect.Descriptor instead.
func (*GetChunksRequest) Descriptor() ([]byte, []int) {
	return file_node_v2_node_v2_proto_rawDescGZIP(), []int{2}
}

func (x *GetChunksRequest) GetBlobKey() []byte {
	if x != nil {
		return x.BlobKey
	}
	return nil
}

func (x *GetChunksRequest) GetQuorumId() uint32 {
	if x != nil {
		return x.QuorumId
	}
	return 0
}

type GetChunksReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// All chunks the Node is storing for the requested blob per RetrieveChunksRequest.
	Chunks [][]byte `protobuf:"bytes,1,rep,name=chunks,proto3" json:"chunks,omitempty"`
}

func (x *GetChunksReply) Reset() {
	*x = GetChunksReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_v2_node_v2_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetChunksReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetChunksReply) ProtoMessage() {}

func (x *GetChunksReply) ProtoReflect() protoreflect.Message {
	mi := &file_node_v2_node_v2_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetChunksReply.ProtoReflect.Descriptor instead.
func (*GetChunksReply) Descriptor() ([]byte, []int) {
	return file_node_v2_node_v2_proto_rawDescGZIP(), []int{3}
}

func (x *GetChunksReply) GetChunks() [][]byte {
	if x != nil {
		return x.Chunks
	}
	return nil
}

type GetBlobCertificateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BlobKey []byte `protobuf:"bytes,1,opt,name=blob_key,json=blobKey,proto3" json:"blob_key,omitempty"`
}

func (x *GetBlobCertificateRequest) Reset() {
	*x = GetBlobCertificateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_v2_node_v2_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetBlobCertificateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetBlobCertificateRequest) ProtoMessage() {}

func (x *GetBlobCertificateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_node_v2_node_v2_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetBlobCertificateRequest.ProtoReflect.Descriptor instead.
func (*GetBlobCertificateRequest) Descriptor() ([]byte, []int) {
	return file_node_v2_node_v2_proto_rawDescGZIP(), []int{4}
}

func (x *GetBlobCertificateRequest) GetBlobKey() []byte {
	if x != nil {
		return x.BlobKey
	}
	return nil
}

type GetBlobCertificateReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BlobCertificate *common.BlobCertificate `protobuf:"bytes,1,opt,name=blob_certificate,json=blobCertificate,proto3" json:"blob_certificate,omitempty"`
}

func (x *GetBlobCertificateReply) Reset() {
	*x = GetBlobCertificateReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_v2_node_v2_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetBlobCertificateReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetBlobCertificateReply) ProtoMessage() {}

func (x *GetBlobCertificateReply) ProtoReflect() protoreflect.Message {
	mi := &file_node_v2_node_v2_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetBlobCertificateReply.ProtoReflect.Descriptor instead.
func (*GetBlobCertificateReply) Descriptor() ([]byte, []int) {
	return file_node_v2_node_v2_proto_rawDescGZIP(), []int{5}
}

func (x *GetBlobCertificateReply) GetBlobCertificate() *common.BlobCertificate {
	if x != nil {
		return x.BlobCertificate
	}
	return nil
}

// Node info request
type NodeInfoRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *NodeInfoRequest) Reset() {
	*x = NodeInfoRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_v2_node_v2_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NodeInfoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeInfoRequest) ProtoMessage() {}

func (x *NodeInfoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_node_v2_node_v2_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeInfoRequest.ProtoReflect.Descriptor instead.
func (*NodeInfoRequest) Descriptor() ([]byte, []int) {
	return file_node_v2_node_v2_proto_rawDescGZIP(), []int{6}
}

// Node info reply
type NodeInfoReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Semver   string `protobuf:"bytes,1,opt,name=semver,proto3" json:"semver,omitempty"`
	Arch     string `protobuf:"bytes,2,opt,name=arch,proto3" json:"arch,omitempty"`
	Os       string `protobuf:"bytes,3,opt,name=os,proto3" json:"os,omitempty"`
	NumCpu   uint32 `protobuf:"varint,4,opt,name=num_cpu,json=numCpu,proto3" json:"num_cpu,omitempty"`
	MemBytes uint64 `protobuf:"varint,5,opt,name=mem_bytes,json=memBytes,proto3" json:"mem_bytes,omitempty"`
}

func (x *NodeInfoReply) Reset() {
	*x = NodeInfoReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_v2_node_v2_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NodeInfoReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeInfoReply) ProtoMessage() {}

func (x *NodeInfoReply) ProtoReflect() protoreflect.Message {
	mi := &file_node_v2_node_v2_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeInfoReply.ProtoReflect.Descriptor instead.
func (*NodeInfoReply) Descriptor() ([]byte, []int) {
	return file_node_v2_node_v2_proto_rawDescGZIP(), []int{7}
}

func (x *NodeInfoReply) GetSemver() string {
	if x != nil {
		return x.Semver
	}
	return ""
}

func (x *NodeInfoReply) GetArch() string {
	if x != nil {
		return x.Arch
	}
	return ""
}

func (x *NodeInfoReply) GetOs() string {
	if x != nil {
		return x.Os
	}
	return ""
}

func (x *NodeInfoReply) GetNumCpu() uint32 {
	if x != nil {
		return x.NumCpu
	}
	return 0
}

func (x *NodeInfoReply) GetMemBytes() uint64 {
	if x != nil {
		return x.MemBytes
	}
	return 0
}

var File_node_v2_node_v2_proto protoreflect.FileDescriptor

var file_node_v2_node_v2_proto_rawDesc = []byte{
	0x0a, 0x15, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x76, 0x32, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x76,
	0x32, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x76, 0x32,
	0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x13, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5a, 0x0a, 0x12, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x43, 0x68,
	0x75, 0x6e, 0x6b, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x44, 0x0a, 0x11, 0x62,
	0x6c, 0x6f, 0x62, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e,
	0x42, 0x6c, 0x6f, 0x62, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52,
	0x10, 0x62, 0x6c, 0x6f, 0x62, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x73, 0x22, 0x4f, 0x0a, 0x10, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x73,
	0x52, 0x65, 0x70, 0x6c, 0x79, 0x12, 0x3b, 0x0a, 0x0a, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x42, 0x79, 0x74, 0x65,
	0x73, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x0a, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x73, 0x22, 0x4a, 0x0a, 0x10, 0x47, 0x65, 0x74, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x73, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x62, 0x6c, 0x6f, 0x62, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x62, 0x6c, 0x6f, 0x62, 0x4b, 0x65,
	0x79, 0x12, 0x1b, 0x0a, 0x09, 0x71, 0x75, 0x6f, 0x72, 0x75, 0x6d, 0x5f, 0x69, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x71, 0x75, 0x6f, 0x72, 0x75, 0x6d, 0x49, 0x64, 0x22, 0x28,
	0x0a, 0x0e, 0x47, 0x65, 0x74, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x73, 0x52, 0x65, 0x70, 0x6c, 0x79,
	0x12, 0x16, 0x0a, 0x06, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x06, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x73, 0x22, 0x36, 0x0a, 0x19, 0x47, 0x65, 0x74, 0x42,
	0x6c, 0x6f, 0x62, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x62, 0x6c, 0x6f, 0x62, 0x5f, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x62, 0x6c, 0x6f, 0x62, 0x4b, 0x65, 0x79,
	0x22, 0x5d, 0x0a, 0x17, 0x47, 0x65, 0x74, 0x42, 0x6c, 0x6f, 0x62, 0x43, 0x65, 0x72, 0x74, 0x69,
	0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x12, 0x42, 0x0a, 0x10, 0x62,
	0x6c, 0x6f, 0x62, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x42,
	0x6c, 0x6f, 0x62, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x0f,
	0x62, 0x6c, 0x6f, 0x62, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x22,
	0x11, 0x0a, 0x0f, 0x4e, 0x6f, 0x64, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x22, 0x81, 0x01, 0x0a, 0x0d, 0x4e, 0x6f, 0x64, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52,
	0x65, 0x70, 0x6c, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x6d, 0x76, 0x65, 0x72, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x65, 0x6d, 0x76, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04,
	0x61, 0x72, 0x63, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x61, 0x72, 0x63, 0x68,
	0x12, 0x0e, 0x0a, 0x02, 0x6f, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x6f, 0x73,
	0x12, 0x17, 0x0a, 0x07, 0x6e, 0x75, 0x6d, 0x5f, 0x63, 0x70, 0x75, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x06, 0x6e, 0x75, 0x6d, 0x43, 0x70, 0x75, 0x12, 0x1b, 0x0a, 0x09, 0x6d, 0x65, 0x6d,
	0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x6d, 0x65,
	0x6d, 0x42, 0x79, 0x74, 0x65, 0x73, 0x32, 0x94, 0x01, 0x0a, 0x09, 0x44, 0x69, 0x73, 0x70, 0x65,
	0x72, 0x73, 0x61, 0x6c, 0x12, 0x47, 0x0a, 0x0b, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x43, 0x68, 0x75,
	0x6e, 0x6b, 0x73, 0x12, 0x1b, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x76, 0x32, 0x2e, 0x53, 0x74,
	0x6f, 0x72, 0x65, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x19, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x76, 0x32, 0x2e, 0x53, 0x74, 0x6f, 0x72, 0x65,
	0x43, 0x68, 0x75, 0x6e, 0x6b, 0x73, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x12, 0x3e, 0x0a,
	0x08, 0x4e, 0x6f, 0x64, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x18, 0x2e, 0x6e, 0x6f, 0x64, 0x65,
	0x2e, 0x76, 0x32, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x76, 0x32, 0x2e, 0x4e, 0x6f,
	0x64, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x32, 0xec, 0x01,
	0x0a, 0x09, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x61, 0x6c, 0x12, 0x41, 0x0a, 0x09, 0x47,
	0x65, 0x74, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x73, 0x12, 0x19, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e,
	0x76, 0x32, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x73, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x76, 0x32, 0x2e, 0x47, 0x65,
	0x74, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x73, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x12, 0x5c,
	0x0a, 0x12, 0x47, 0x65, 0x74, 0x42, 0x6c, 0x6f, 0x62, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x12, 0x22, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x76, 0x32, 0x2e, 0x47,
	0x65, 0x74, 0x42, 0x6c, 0x6f, 0x62, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x20, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e,
	0x76, 0x32, 0x2e, 0x47, 0x65, 0x74, 0x42, 0x6c, 0x6f, 0x62, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x12, 0x3e, 0x0a, 0x08,
	0x4e, 0x6f, 0x64, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x18, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e,
	0x76, 0x32, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x16, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x76, 0x32, 0x2e, 0x4e, 0x6f, 0x64,
	0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x42, 0x2f, 0x5a, 0x2d,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4c, 0x61, 0x79, 0x72, 0x2d,
	0x4c, 0x61, 0x62, 0x73, 0x2f, 0x65, 0x69, 0x67, 0x65, 0x6e, 0x64, 0x61, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x76, 0x32, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_node_v2_node_v2_proto_rawDescOnce sync.Once
	file_node_v2_node_v2_proto_rawDescData = file_node_v2_node_v2_proto_rawDesc
)

func file_node_v2_node_v2_proto_rawDescGZIP() []byte {
	file_node_v2_node_v2_proto_rawDescOnce.Do(func() {
		file_node_v2_node_v2_proto_rawDescData = protoimpl.X.CompressGZIP(file_node_v2_node_v2_proto_rawDescData)
	})
	return file_node_v2_node_v2_proto_rawDescData
}

var file_node_v2_node_v2_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_node_v2_node_v2_proto_goTypes = []interface{}{
	(*StoreChunksRequest)(nil),        // 0: node.v2.StoreChunksRequest
	(*StoreChunksReply)(nil),          // 1: node.v2.StoreChunksReply
	(*GetChunksRequest)(nil),          // 2: node.v2.GetChunksRequest
	(*GetChunksReply)(nil),            // 3: node.v2.GetChunksReply
	(*GetBlobCertificateRequest)(nil), // 4: node.v2.GetBlobCertificateRequest
	(*GetBlobCertificateReply)(nil),   // 5: node.v2.GetBlobCertificateReply
	(*NodeInfoRequest)(nil),           // 6: node.v2.NodeInfoRequest
	(*NodeInfoReply)(nil),             // 7: node.v2.NodeInfoReply
	(*common.BlobCertificate)(nil),    // 8: common.BlobCertificate
	(*wrapperspb.BytesValue)(nil),     // 9: google.protobuf.BytesValue
}
var file_node_v2_node_v2_proto_depIdxs = []int32{
	8, // 0: node.v2.StoreChunksRequest.blob_certificates:type_name -> common.BlobCertificate
	9, // 1: node.v2.StoreChunksReply.signatures:type_name -> google.protobuf.BytesValue
	8, // 2: node.v2.GetBlobCertificateReply.blob_certificate:type_name -> common.BlobCertificate
	0, // 3: node.v2.Dispersal.StoreChunks:input_type -> node.v2.StoreChunksRequest
	6, // 4: node.v2.Dispersal.NodeInfo:input_type -> node.v2.NodeInfoRequest
	2, // 5: node.v2.Retrieval.GetChunks:input_type -> node.v2.GetChunksRequest
	4, // 6: node.v2.Retrieval.GetBlobCertificate:input_type -> node.v2.GetBlobCertificateRequest
	6, // 7: node.v2.Retrieval.NodeInfo:input_type -> node.v2.NodeInfoRequest
	1, // 8: node.v2.Dispersal.StoreChunks:output_type -> node.v2.StoreChunksReply
	7, // 9: node.v2.Dispersal.NodeInfo:output_type -> node.v2.NodeInfoReply
	3, // 10: node.v2.Retrieval.GetChunks:output_type -> node.v2.GetChunksReply
	5, // 11: node.v2.Retrieval.GetBlobCertificate:output_type -> node.v2.GetBlobCertificateReply
	7, // 12: node.v2.Retrieval.NodeInfo:output_type -> node.v2.NodeInfoReply
	8, // [8:13] is the sub-list for method output_type
	3, // [3:8] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_node_v2_node_v2_proto_init() }
func file_node_v2_node_v2_proto_init() {
	if File_node_v2_node_v2_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_node_v2_node_v2_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StoreChunksRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_node_v2_node_v2_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StoreChunksReply); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_node_v2_node_v2_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetChunksRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_node_v2_node_v2_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetChunksReply); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_node_v2_node_v2_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetBlobCertificateRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_node_v2_node_v2_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetBlobCertificateReply); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_node_v2_node_v2_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NodeInfoRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_node_v2_node_v2_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NodeInfoReply); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_node_v2_node_v2_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   2,
		},
		GoTypes:           file_node_v2_node_v2_proto_goTypes,
		DependencyIndexes: file_node_v2_node_v2_proto_depIdxs,
		MessageInfos:      file_node_v2_node_v2_proto_msgTypes,
	}.Build()
	File_node_v2_node_v2_proto = out.File
	file_node_v2_node_v2_proto_rawDesc = nil
	file_node_v2_node_v2_proto_goTypes = nil
	file_node_v2_node_v2_proto_depIdxs = nil
}