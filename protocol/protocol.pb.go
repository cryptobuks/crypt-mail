// Code generated by protoc-gen-go. DO NOT EDIT.
// source: protocol.proto

package protocol

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type HandShakeRequest struct {
	SessionId            uint64   `protobuf:"varint,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HandShakeRequest) Reset()         { *m = HandShakeRequest{} }
func (m *HandShakeRequest) String() string { return proto.CompactTextString(m) }
func (*HandShakeRequest) ProtoMessage()    {}
func (*HandShakeRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2bc2336598a3f7e0, []int{0}
}

func (m *HandShakeRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HandShakeRequest.Unmarshal(m, b)
}
func (m *HandShakeRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HandShakeRequest.Marshal(b, m, deterministic)
}
func (m *HandShakeRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HandShakeRequest.Merge(m, src)
}
func (m *HandShakeRequest) XXX_Size() int {
	return xxx_messageInfo_HandShakeRequest.Size(m)
}
func (m *HandShakeRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_HandShakeRequest.DiscardUnknown(m)
}

var xxx_messageInfo_HandShakeRequest proto.InternalMessageInfo

func (m *HandShakeRequest) GetSessionId() uint64 {
	if m != nil {
		return m.SessionId
	}
	return 0
}

type HandShakeResponse struct {
	SessionId            uint64   `protobuf:"varint,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	PubKey               string   `protobuf:"bytes,2,opt,name=pub_key,json=pubKey,proto3" json:"pub_key,omitempty"`
	PrivKey              string   `protobuf:"bytes,3,opt,name=priv_key,json=privKey,proto3" json:"priv_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HandShakeResponse) Reset()         { *m = HandShakeResponse{} }
func (m *HandShakeResponse) String() string { return proto.CompactTextString(m) }
func (*HandShakeResponse) ProtoMessage()    {}
func (*HandShakeResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2bc2336598a3f7e0, []int{1}
}

func (m *HandShakeResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HandShakeResponse.Unmarshal(m, b)
}
func (m *HandShakeResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HandShakeResponse.Marshal(b, m, deterministic)
}
func (m *HandShakeResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HandShakeResponse.Merge(m, src)
}
func (m *HandShakeResponse) XXX_Size() int {
	return xxx_messageInfo_HandShakeResponse.Size(m)
}
func (m *HandShakeResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_HandShakeResponse.DiscardUnknown(m)
}

var xxx_messageInfo_HandShakeResponse proto.InternalMessageInfo

func (m *HandShakeResponse) GetSessionId() uint64 {
	if m != nil {
		return m.SessionId
	}
	return 0
}

func (m *HandShakeResponse) GetPubKey() string {
	if m != nil {
		return m.PubKey
	}
	return ""
}

func (m *HandShakeResponse) GetPrivKey() string {
	if m != nil {
		return m.PrivKey
	}
	return ""
}

type QueryRequest struct {
	SessionId            uint64   `protobuf:"varint,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	Name                 string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *QueryRequest) Reset()         { *m = QueryRequest{} }
func (m *QueryRequest) String() string { return proto.CompactTextString(m) }
func (*QueryRequest) ProtoMessage()    {}
func (*QueryRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2bc2336598a3f7e0, []int{2}
}

func (m *QueryRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_QueryRequest.Unmarshal(m, b)
}
func (m *QueryRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_QueryRequest.Marshal(b, m, deterministic)
}
func (m *QueryRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryRequest.Merge(m, src)
}
func (m *QueryRequest) XXX_Size() int {
	return xxx_messageInfo_QueryRequest.Size(m)
}
func (m *QueryRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryRequest proto.InternalMessageInfo

func (m *QueryRequest) GetSessionId() uint64 {
	if m != nil {
		return m.SessionId
	}
	return 0
}

func (m *QueryRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type QueryResponse struct {
	SessionId            uint64     `protobuf:"varint,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	Accounts             []*Account `protobuf:"bytes,2,rep,name=accounts,proto3" json:"accounts,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *QueryResponse) Reset()         { *m = QueryResponse{} }
func (m *QueryResponse) String() string { return proto.CompactTextString(m) }
func (*QueryResponse) ProtoMessage()    {}
func (*QueryResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2bc2336598a3f7e0, []int{3}
}

func (m *QueryResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_QueryResponse.Unmarshal(m, b)
}
func (m *QueryResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_QueryResponse.Marshal(b, m, deterministic)
}
func (m *QueryResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryResponse.Merge(m, src)
}
func (m *QueryResponse) XXX_Size() int {
	return xxx_messageInfo_QueryResponse.Size(m)
}
func (m *QueryResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryResponse proto.InternalMessageInfo

func (m *QueryResponse) GetSessionId() uint64 {
	if m != nil {
		return m.SessionId
	}
	return 0
}

func (m *QueryResponse) GetAccounts() []*Account {
	if m != nil {
		return m.Accounts
	}
	return nil
}

type LockRequest struct {
	SessionId            uint64   `protobuf:"varint,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	Name                 string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LockRequest) Reset()         { *m = LockRequest{} }
func (m *LockRequest) String() string { return proto.CompactTextString(m) }
func (*LockRequest) ProtoMessage()    {}
func (*LockRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2bc2336598a3f7e0, []int{4}
}

func (m *LockRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LockRequest.Unmarshal(m, b)
}
func (m *LockRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LockRequest.Marshal(b, m, deterministic)
}
func (m *LockRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LockRequest.Merge(m, src)
}
func (m *LockRequest) XXX_Size() int {
	return xxx_messageInfo_LockRequest.Size(m)
}
func (m *LockRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_LockRequest.DiscardUnknown(m)
}

var xxx_messageInfo_LockRequest proto.InternalMessageInfo

func (m *LockRequest) GetSessionId() uint64 {
	if m != nil {
		return m.SessionId
	}
	return 0
}

func (m *LockRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type LockResponse struct {
	SessionId            uint64   `protobuf:"varint,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	Status               bool     `protobuf:"varint,2,opt,name=status,proto3" json:"status,omitempty"`
	Msg                  string   `protobuf:"bytes,3,opt,name=msg,proto3" json:"msg,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LockResponse) Reset()         { *m = LockResponse{} }
func (m *LockResponse) String() string { return proto.CompactTextString(m) }
func (*LockResponse) ProtoMessage()    {}
func (*LockResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2bc2336598a3f7e0, []int{5}
}

func (m *LockResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LockResponse.Unmarshal(m, b)
}
func (m *LockResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LockResponse.Marshal(b, m, deterministic)
}
func (m *LockResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LockResponse.Merge(m, src)
}
func (m *LockResponse) XXX_Size() int {
	return xxx_messageInfo_LockResponse.Size(m)
}
func (m *LockResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_LockResponse.DiscardUnknown(m)
}

var xxx_messageInfo_LockResponse proto.InternalMessageInfo

func (m *LockResponse) GetSessionId() uint64 {
	if m != nil {
		return m.SessionId
	}
	return 0
}

func (m *LockResponse) GetStatus() bool {
	if m != nil {
		return m.Status
	}
	return false
}

func (m *LockResponse) GetMsg() string {
	if m != nil {
		return m.Msg
	}
	return ""
}

type UnlockRequest struct {
	SessionId            uint64   `protobuf:"varint,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	Name                 string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Cipher               string   `protobuf:"bytes,3,opt,name=cipher,proto3" json:"cipher,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UnlockRequest) Reset()         { *m = UnlockRequest{} }
func (m *UnlockRequest) String() string { return proto.CompactTextString(m) }
func (*UnlockRequest) ProtoMessage()    {}
func (*UnlockRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2bc2336598a3f7e0, []int{6}
}

func (m *UnlockRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UnlockRequest.Unmarshal(m, b)
}
func (m *UnlockRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UnlockRequest.Marshal(b, m, deterministic)
}
func (m *UnlockRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UnlockRequest.Merge(m, src)
}
func (m *UnlockRequest) XXX_Size() int {
	return xxx_messageInfo_UnlockRequest.Size(m)
}
func (m *UnlockRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_UnlockRequest.DiscardUnknown(m)
}

var xxx_messageInfo_UnlockRequest proto.InternalMessageInfo

func (m *UnlockRequest) GetSessionId() uint64 {
	if m != nil {
		return m.SessionId
	}
	return 0
}

func (m *UnlockRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *UnlockRequest) GetCipher() string {
	if m != nil {
		return m.Cipher
	}
	return ""
}

type UnlockResponse struct {
	SessionId            uint64   `protobuf:"varint,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	Status               bool     `protobuf:"varint,2,opt,name=status,proto3" json:"status,omitempty"`
	Msg                  string   `protobuf:"bytes,3,opt,name=msg,proto3" json:"msg,omitempty"`
	EncryptAccount       []byte   `protobuf:"bytes,4,opt,name=encrypt_account,json=encryptAccount,proto3" json:"encrypt_account,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UnlockResponse) Reset()         { *m = UnlockResponse{} }
func (m *UnlockResponse) String() string { return proto.CompactTextString(m) }
func (*UnlockResponse) ProtoMessage()    {}
func (*UnlockResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2bc2336598a3f7e0, []int{7}
}

func (m *UnlockResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UnlockResponse.Unmarshal(m, b)
}
func (m *UnlockResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UnlockResponse.Marshal(b, m, deterministic)
}
func (m *UnlockResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UnlockResponse.Merge(m, src)
}
func (m *UnlockResponse) XXX_Size() int {
	return xxx_messageInfo_UnlockResponse.Size(m)
}
func (m *UnlockResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_UnlockResponse.DiscardUnknown(m)
}

var xxx_messageInfo_UnlockResponse proto.InternalMessageInfo

func (m *UnlockResponse) GetSessionId() uint64 {
	if m != nil {
		return m.SessionId
	}
	return 0
}

func (m *UnlockResponse) GetStatus() bool {
	if m != nil {
		return m.Status
	}
	return false
}

func (m *UnlockResponse) GetMsg() string {
	if m != nil {
		return m.Msg
	}
	return ""
}

func (m *UnlockResponse) GetEncryptAccount() []byte {
	if m != nil {
		return m.EncryptAccount
	}
	return nil
}

type SaveRequest struct {
	SessionId            uint64   `protobuf:"varint,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	Name                 string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Account              *Account `protobuf:"bytes,3,opt,name=account,proto3" json:"account,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SaveRequest) Reset()         { *m = SaveRequest{} }
func (m *SaveRequest) String() string { return proto.CompactTextString(m) }
func (*SaveRequest) ProtoMessage()    {}
func (*SaveRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2bc2336598a3f7e0, []int{8}
}

func (m *SaveRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SaveRequest.Unmarshal(m, b)
}
func (m *SaveRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SaveRequest.Marshal(b, m, deterministic)
}
func (m *SaveRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SaveRequest.Merge(m, src)
}
func (m *SaveRequest) XXX_Size() int {
	return xxx_messageInfo_SaveRequest.Size(m)
}
func (m *SaveRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_SaveRequest.DiscardUnknown(m)
}

var xxx_messageInfo_SaveRequest proto.InternalMessageInfo

func (m *SaveRequest) GetSessionId() uint64 {
	if m != nil {
		return m.SessionId
	}
	return 0
}

func (m *SaveRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *SaveRequest) GetAccount() *Account {
	if m != nil {
		return m.Account
	}
	return nil
}

type SaveResponse struct {
	SessionId            uint64   `protobuf:"varint,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	Status               bool     `protobuf:"varint,2,opt,name=status,proto3" json:"status,omitempty"`
	Msg                  string   `protobuf:"bytes,3,opt,name=msg,proto3" json:"msg,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SaveResponse) Reset()         { *m = SaveResponse{} }
func (m *SaveResponse) String() string { return proto.CompactTextString(m) }
func (*SaveResponse) ProtoMessage()    {}
func (*SaveResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2bc2336598a3f7e0, []int{9}
}

func (m *SaveResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SaveResponse.Unmarshal(m, b)
}
func (m *SaveResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SaveResponse.Marshal(b, m, deterministic)
}
func (m *SaveResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SaveResponse.Merge(m, src)
}
func (m *SaveResponse) XXX_Size() int {
	return xxx_messageInfo_SaveResponse.Size(m)
}
func (m *SaveResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SaveResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SaveResponse proto.InternalMessageInfo

func (m *SaveResponse) GetSessionId() uint64 {
	if m != nil {
		return m.SessionId
	}
	return 0
}

func (m *SaveResponse) GetStatus() bool {
	if m != nil {
		return m.Status
	}
	return false
}

func (m *SaveResponse) GetMsg() string {
	if m != nil {
		return m.Msg
	}
	return ""
}

func init() {
	proto.RegisterType((*HandShakeRequest)(nil), "protocol.HandShakeRequest")
	proto.RegisterType((*HandShakeResponse)(nil), "protocol.HandShakeResponse")
	proto.RegisterType((*QueryRequest)(nil), "protocol.QueryRequest")
	proto.RegisterType((*QueryResponse)(nil), "protocol.QueryResponse")
	proto.RegisterType((*LockRequest)(nil), "protocol.LockRequest")
	proto.RegisterType((*LockResponse)(nil), "protocol.LockResponse")
	proto.RegisterType((*UnlockRequest)(nil), "protocol.UnlockRequest")
	proto.RegisterType((*UnlockResponse)(nil), "protocol.UnlockResponse")
	proto.RegisterType((*SaveRequest)(nil), "protocol.SaveRequest")
	proto.RegisterType((*SaveResponse)(nil), "protocol.SaveResponse")
}

func init() { proto.RegisterFile("protocol.proto", fileDescriptor_2bc2336598a3f7e0) }

var fileDescriptor_2bc2336598a3f7e0 = []byte{
	// 426 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x53, 0xdf, 0x4b, 0xfa, 0x50,
	0x14, 0x67, 0x3a, 0xe7, 0x3c, 0xfe, 0xf8, 0xea, 0x85, 0xaf, 0xae, 0x45, 0x30, 0xee, 0x4b, 0x83,
	0x48, 0xc8, 0x08, 0x82, 0x5e, 0x12, 0x7a, 0x28, 0xec, 0xa5, 0x49, 0x04, 0x41, 0xc8, 0x9c, 0xb7,
	0x1c, 0xea, 0xb6, 0x76, 0x37, 0x61, 0xaf, 0xfd, 0x49, 0xfd, 0x85, 0xb1, 0xed, 0xce, 0xdd, 0x54,
	0x48, 0xd0, 0xb7, 0x7b, 0x7e, 0x7d, 0xce, 0xe7, 0x7e, 0xce, 0x39, 0xd0, 0xf0, 0x7c, 0x37, 0x70,
	0x2d, 0x77, 0xde, 0x4d, 0x1e, 0x48, 0xce, 0x6c, 0xb5, 0x6e, 0x5a, 0x96, 0x1b, 0x3a, 0x41, 0x1a,
	0xc0, 0x17, 0xd0, 0xbc, 0x37, 0x9d, 0xc9, 0x70, 0x6a, 0xce, 0x88, 0x41, 0x3e, 0x43, 0x42, 0x03,
	0x74, 0x02, 0x40, 0x09, 0xa5, 0xb6, 0xeb, 0x8c, 0xec, 0x89, 0x22, 0x68, 0x82, 0x2e, 0x1a, 0x15,
	0xe6, 0x79, 0x98, 0xe0, 0x77, 0x68, 0x71, 0x25, 0xd4, 0x73, 0x1d, 0x4a, 0xfe, 0xa8, 0x41, 0x1d,
	0x28, 0x7b, 0xe1, 0x78, 0x34, 0x23, 0x91, 0x52, 0xd0, 0x04, 0xbd, 0x62, 0x48, 0x5e, 0x38, 0x1e,
	0x90, 0x08, 0x1d, 0x81, 0xec, 0xf9, 0xf6, 0x32, 0x89, 0x14, 0x93, 0x48, 0x39, 0xb6, 0x07, 0x24,
	0xc2, 0x7d, 0xa8, 0x3d, 0x85, 0xc4, 0x8f, 0x76, 0xa3, 0x85, 0x10, 0x88, 0x8e, 0xb9, 0x20, 0x0c,
	0x3f, 0x79, 0xe3, 0x37, 0xa8, 0x33, 0x88, 0xdd, 0x68, 0x9e, 0x83, 0xcc, 0xe4, 0xa1, 0x4a, 0x41,
	0x2b, 0xea, 0xd5, 0x5e, 0xab, 0xbb, 0x52, 0xb2, 0x9f, 0x46, 0x8c, 0x55, 0x0a, 0xbe, 0x85, 0xea,
	0xa3, 0x6b, 0xcd, 0xf6, 0x20, 0xf8, 0x02, 0xb5, 0x14, 0x61, 0x37, 0x7e, 0x6d, 0x90, 0x68, 0x60,
	0x06, 0x21, 0x4d, 0x40, 0x64, 0x83, 0x59, 0xa8, 0x09, 0xc5, 0x05, 0xfd, 0x60, 0x02, 0xc6, 0x4f,
	0xfc, 0x0a, 0xf5, 0x67, 0x67, 0xbe, 0x17, 0xb9, 0xb8, 0x9b, 0x65, 0x7b, 0x53, 0xe2, 0x33, 0x60,
	0x66, 0xe1, 0x2f, 0x01, 0x1a, 0x19, 0xf8, 0x81, 0x79, 0xa3, 0x53, 0xf8, 0x47, 0x1c, 0xcb, 0x8f,
	0xbc, 0x60, 0xc4, 0x64, 0x56, 0x44, 0x4d, 0xd0, 0x6b, 0x46, 0x83, 0xb9, 0xd9, 0x14, 0xf0, 0x02,
	0xaa, 0x43, 0x73, 0x49, 0xf6, 0xf8, 0xde, 0x19, 0x94, 0xb3, 0x16, 0x31, 0x81, 0xad, 0xb3, 0xce,
	0x32, 0xe2, 0x41, 0xa5, 0xed, 0x0e, 0xfc, 0xe1, 0xde, 0x77, 0x01, 0x4a, 0xfd, 0xb9, 0x6d, 0x11,
	0x74, 0x07, 0x95, 0xd5, 0x5d, 0x21, 0x35, 0xe7, 0xb2, 0x7e, 0x9f, 0xea, 0xf1, 0xd6, 0x18, 0x23,
	0x76, 0x0d, 0xa5, 0x64, 0xe5, 0x51, 0x3b, 0xcf, 0xe2, 0xcf, 0x48, 0xed, 0x6c, 0xf8, 0x59, 0xe5,
	0x15, 0x88, 0xf1, 0x2e, 0xa2, 0xff, 0x79, 0x02, 0xb7, 0xdd, 0x6a, 0x7b, 0xdd, 0xcd, 0xca, 0x6e,
	0x40, 0x4a, 0x97, 0x01, 0x71, 0xc8, 0xbf, 0x76, 0x4f, 0x55, 0x36, 0x03, 0x79, 0xcf, 0x58, 0x56,
	0xbe, 0x27, 0x37, 0x55, 0xbe, 0x27, 0xaf, 0xfe, 0x58, 0x4a, 0xdc, 0x97, 0x3f, 0x01, 0x00, 0x00,
	0xff, 0xff, 0xa9, 0x7f, 0xe4, 0x81, 0xe7, 0x04, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AliceClient is the client API for Alice service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AliceClient interface {
	HandShake(ctx context.Context, in *HandShakeRequest, opts ...grpc.CallOption) (*HandShakeResponse, error)
	Query(ctx context.Context, in *QueryRequest, opts ...grpc.CallOption) (*QueryResponse, error)
	Lock(ctx context.Context, in *LockRequest, opts ...grpc.CallOption) (*LockResponse, error)
	// maybe split the action to unlock and load would be better
	Unlock(ctx context.Context, in *UnlockRequest, opts ...grpc.CallOption) (*UnlockResponse, error)
	Save(ctx context.Context, in *SaveRequest, opts ...grpc.CallOption) (*SaveResponse, error)
}

type aliceClient struct {
	cc *grpc.ClientConn
}

func NewAliceClient(cc *grpc.ClientConn) AliceClient {
	return &aliceClient{cc}
}

func (c *aliceClient) HandShake(ctx context.Context, in *HandShakeRequest, opts ...grpc.CallOption) (*HandShakeResponse, error) {
	out := new(HandShakeResponse)
	err := c.cc.Invoke(ctx, "/protocol.Alice/HandShake", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aliceClient) Query(ctx context.Context, in *QueryRequest, opts ...grpc.CallOption) (*QueryResponse, error) {
	out := new(QueryResponse)
	err := c.cc.Invoke(ctx, "/protocol.Alice/Query", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aliceClient) Lock(ctx context.Context, in *LockRequest, opts ...grpc.CallOption) (*LockResponse, error) {
	out := new(LockResponse)
	err := c.cc.Invoke(ctx, "/protocol.Alice/Lock", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aliceClient) Unlock(ctx context.Context, in *UnlockRequest, opts ...grpc.CallOption) (*UnlockResponse, error) {
	out := new(UnlockResponse)
	err := c.cc.Invoke(ctx, "/protocol.Alice/Unlock", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aliceClient) Save(ctx context.Context, in *SaveRequest, opts ...grpc.CallOption) (*SaveResponse, error) {
	out := new(SaveResponse)
	err := c.cc.Invoke(ctx, "/protocol.Alice/Save", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AliceServer is the server API for Alice service.
type AliceServer interface {
	HandShake(context.Context, *HandShakeRequest) (*HandShakeResponse, error)
	Query(context.Context, *QueryRequest) (*QueryResponse, error)
	Lock(context.Context, *LockRequest) (*LockResponse, error)
	// maybe split the action to unlock and load would be better
	Unlock(context.Context, *UnlockRequest) (*UnlockResponse, error)
	Save(context.Context, *SaveRequest) (*SaveResponse, error)
}

func RegisterAliceServer(s *grpc.Server, srv AliceServer) {
	s.RegisterService(&_Alice_serviceDesc, srv)
}

func _Alice_HandShake_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HandShakeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AliceServer).HandShake(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protocol.Alice/HandShake",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AliceServer).HandShake(ctx, req.(*HandShakeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Alice_Query_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AliceServer).Query(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protocol.Alice/Query",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AliceServer).Query(ctx, req.(*QueryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Alice_Lock_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LockRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AliceServer).Lock(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protocol.Alice/Lock",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AliceServer).Lock(ctx, req.(*LockRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Alice_Unlock_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UnlockRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AliceServer).Unlock(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protocol.Alice/Unlock",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AliceServer).Unlock(ctx, req.(*UnlockRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Alice_Save_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SaveRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AliceServer).Save(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protocol.Alice/Save",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AliceServer).Save(ctx, req.(*SaveRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Alice_serviceDesc = grpc.ServiceDesc{
	ServiceName: "protocol.Alice",
	HandlerType: (*AliceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "HandShake",
			Handler:    _Alice_HandShake_Handler,
		},
		{
			MethodName: "Query",
			Handler:    _Alice_Query_Handler,
		},
		{
			MethodName: "Lock",
			Handler:    _Alice_Lock_Handler,
		},
		{
			MethodName: "Unlock",
			Handler:    _Alice_Unlock_Handler,
		},
		{
			MethodName: "Save",
			Handler:    _Alice_Save_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "protocol.proto",
}
