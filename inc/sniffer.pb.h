// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: sniffer.proto

#ifndef PROTOBUF_sniffer_2eproto__INCLUDED
#define PROTOBUF_sniffer_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 2005000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 2005000 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_enum_reflection.h>
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)

// Internal implementation detail -- do not call these.
void  protobuf_AddDesc_sniffer_2eproto();
void protobuf_AssignDesc_sniffer_2eproto();
void protobuf_ShutdownFile_sniffer_2eproto();

class SnifferQuery;
class SnifferResponse;
class SnifferResponse_RSSIRecord;

enum QueryType {
  STATUS_REQUEST = 0,
  DATA_REQUEST = 1
};
bool QueryType_IsValid(int value);
const QueryType QueryType_MIN = STATUS_REQUEST;
const QueryType QueryType_MAX = DATA_REQUEST;
const int QueryType_ARRAYSIZE = QueryType_MAX + 1;

const ::google::protobuf::EnumDescriptor* QueryType_descriptor();
inline const ::std::string& QueryType_Name(QueryType value) {
  return ::google::protobuf::internal::NameOfEnum(
    QueryType_descriptor(), value);
}
inline bool QueryType_Parse(
    const ::std::string& name, QueryType* value) {
  return ::google::protobuf::internal::ParseNamedEnum<QueryType>(
    QueryType_descriptor(), name, value);
}
enum ResponseType {
  DATA = 0,
  STATUS = 1
};
bool ResponseType_IsValid(int value);
const ResponseType ResponseType_MIN = DATA;
const ResponseType ResponseType_MAX = STATUS;
const int ResponseType_ARRAYSIZE = ResponseType_MAX + 1;

const ::google::protobuf::EnumDescriptor* ResponseType_descriptor();
inline const ::std::string& ResponseType_Name(ResponseType value) {
  return ::google::protobuf::internal::NameOfEnum(
    ResponseType_descriptor(), value);
}
inline bool ResponseType_Parse(
    const ::std::string& name, ResponseType* value) {
  return ::google::protobuf::internal::ParseNamedEnum<ResponseType>(
    ResponseType_descriptor(), name, value);
}
enum SnifferStatus {
  SNIFFING_STOPED = 0,
  SNIFFING_RUN = 1
};
bool SnifferStatus_IsValid(int value);
const SnifferStatus SnifferStatus_MIN = SNIFFING_STOPED;
const SnifferStatus SnifferStatus_MAX = SNIFFING_RUN;
const int SnifferStatus_ARRAYSIZE = SnifferStatus_MAX + 1;

const ::google::protobuf::EnumDescriptor* SnifferStatus_descriptor();
inline const ::std::string& SnifferStatus_Name(SnifferStatus value) {
  return ::google::protobuf::internal::NameOfEnum(
    SnifferStatus_descriptor(), value);
}
inline bool SnifferStatus_Parse(
    const ::std::string& name, SnifferStatus* value) {
  return ::google::protobuf::internal::ParseNamedEnum<SnifferStatus>(
    SnifferStatus_descriptor(), name, value);
}
// ===================================================================

class SnifferQuery : public ::google::protobuf::Message {
 public:
  SnifferQuery();
  virtual ~SnifferQuery();

  SnifferQuery(const SnifferQuery& from);

  inline SnifferQuery& operator=(const SnifferQuery& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const SnifferQuery& default_instance();

  void Swap(SnifferQuery* other);

  // implements Message ----------------------------------------------

  SnifferQuery* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const SnifferQuery& from);
  void MergeFrom(const SnifferQuery& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // required .QueryType type = 1 [default = DATA_REQUEST];
  inline bool has_type() const;
  inline void clear_type();
  static const int kTypeFieldNumber = 1;
  inline ::QueryType type() const;
  inline void set_type(::QueryType value);

  // optional int32 record_id = 2;
  inline bool has_record_id() const;
  inline void clear_record_id();
  static const int kRecordIdFieldNumber = 2;
  inline ::google::protobuf::int32 record_id() const;
  inline void set_record_id(::google::protobuf::int32 value);

  // @@protoc_insertion_point(class_scope:SnifferQuery)
 private:
  inline void set_has_type();
  inline void clear_has_type();
  inline void set_has_record_id();
  inline void clear_has_record_id();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  int type_;
  ::google::protobuf::int32 record_id_;

  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(2 + 31) / 32];

  friend void  protobuf_AddDesc_sniffer_2eproto();
  friend void protobuf_AssignDesc_sniffer_2eproto();
  friend void protobuf_ShutdownFile_sniffer_2eproto();

  void InitAsDefaultInstance();
  static SnifferQuery* default_instance_;
};
// -------------------------------------------------------------------

class SnifferResponse_RSSIRecord : public ::google::protobuf::Message {
 public:
  SnifferResponse_RSSIRecord();
  virtual ~SnifferResponse_RSSIRecord();

  SnifferResponse_RSSIRecord(const SnifferResponse_RSSIRecord& from);

  inline SnifferResponse_RSSIRecord& operator=(const SnifferResponse_RSSIRecord& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const SnifferResponse_RSSIRecord& default_instance();

  void Swap(SnifferResponse_RSSIRecord* other);

  // implements Message ----------------------------------------------

  SnifferResponse_RSSIRecord* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const SnifferResponse_RSSIRecord& from);
  void MergeFrom(const SnifferResponse_RSSIRecord& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // optional bytes mac = 1;
  inline bool has_mac() const;
  inline void clear_mac();
  static const int kMacFieldNumber = 1;
  inline const ::std::string& mac() const;
  inline void set_mac(const ::std::string& value);
  inline void set_mac(const char* value);
  inline void set_mac(const void* value, size_t size);
  inline ::std::string* mutable_mac();
  inline ::std::string* release_mac();
  inline void set_allocated_mac(::std::string* mac);

  // optional int32 rssi = 2;
  inline bool has_rssi() const;
  inline void clear_rssi();
  static const int kRssiFieldNumber = 2;
  inline ::google::protobuf::int32 rssi() const;
  inline void set_rssi(::google::protobuf::int32 value);

  // optional int32 id = 3;
  inline bool has_id() const;
  inline void clear_id();
  static const int kIdFieldNumber = 3;
  inline ::google::protobuf::int32 id() const;
  inline void set_id(::google::protobuf::int32 value);

  // @@protoc_insertion_point(class_scope:SnifferResponse.RSSIRecord)
 private:
  inline void set_has_mac();
  inline void clear_has_mac();
  inline void set_has_rssi();
  inline void clear_has_rssi();
  inline void set_has_id();
  inline void clear_has_id();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::std::string* mac_;
  ::google::protobuf::int32 rssi_;
  ::google::protobuf::int32 id_;

  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(3 + 31) / 32];

  friend void  protobuf_AddDesc_sniffer_2eproto();
  friend void protobuf_AssignDesc_sniffer_2eproto();
  friend void protobuf_ShutdownFile_sniffer_2eproto();

  void InitAsDefaultInstance();
  static SnifferResponse_RSSIRecord* default_instance_;
};
// -------------------------------------------------------------------

class SnifferResponse : public ::google::protobuf::Message {
 public:
  SnifferResponse();
  virtual ~SnifferResponse();

  SnifferResponse(const SnifferResponse& from);

  inline SnifferResponse& operator=(const SnifferResponse& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const SnifferResponse& default_instance();

  void Swap(SnifferResponse* other);

  // implements Message ----------------------------------------------

  SnifferResponse* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const SnifferResponse& from);
  void MergeFrom(const SnifferResponse& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  typedef SnifferResponse_RSSIRecord RSSIRecord;

  // accessors -------------------------------------------------------

  // required .ResponseType type = 1 [default = DATA];
  inline bool has_type() const;
  inline void clear_type();
  static const int kTypeFieldNumber = 1;
  inline ::ResponseType type() const;
  inline void set_type(::ResponseType value);

  // optional bool interrupted = 2;
  inline bool has_interrupted() const;
  inline void clear_interrupted();
  static const int kInterruptedFieldNumber = 2;
  inline bool interrupted() const;
  inline void set_interrupted(bool value);

  // repeated .SnifferResponse.RSSIRecord rssi_data = 3;
  inline int rssi_data_size() const;
  inline void clear_rssi_data();
  static const int kRssiDataFieldNumber = 3;
  inline const ::SnifferResponse_RSSIRecord& rssi_data(int index) const;
  inline ::SnifferResponse_RSSIRecord* mutable_rssi_data(int index);
  inline ::SnifferResponse_RSSIRecord* add_rssi_data();
  inline const ::google::protobuf::RepeatedPtrField< ::SnifferResponse_RSSIRecord >&
      rssi_data() const;
  inline ::google::protobuf::RepeatedPtrField< ::SnifferResponse_RSSIRecord >*
      mutable_rssi_data();

  // optional .SnifferStatus status = 4;
  inline bool has_status() const;
  inline void clear_status();
  static const int kStatusFieldNumber = 4;
  inline ::SnifferStatus status() const;
  inline void set_status(::SnifferStatus value);

  // @@protoc_insertion_point(class_scope:SnifferResponse)
 private:
  inline void set_has_type();
  inline void clear_has_type();
  inline void set_has_interrupted();
  inline void clear_has_interrupted();
  inline void set_has_status();
  inline void clear_has_status();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  int type_;
  bool interrupted_;
  ::google::protobuf::RepeatedPtrField< ::SnifferResponse_RSSIRecord > rssi_data_;
  int status_;

  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(4 + 31) / 32];

  friend void  protobuf_AddDesc_sniffer_2eproto();
  friend void protobuf_AssignDesc_sniffer_2eproto();
  friend void protobuf_ShutdownFile_sniffer_2eproto();

  void InitAsDefaultInstance();
  static SnifferResponse* default_instance_;
};
// ===================================================================


// ===================================================================

// SnifferQuery

// required .QueryType type = 1 [default = DATA_REQUEST];
inline bool SnifferQuery::has_type() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void SnifferQuery::set_has_type() {
  _has_bits_[0] |= 0x00000001u;
}
inline void SnifferQuery::clear_has_type() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void SnifferQuery::clear_type() {
  type_ = 1;
  clear_has_type();
}
inline ::QueryType SnifferQuery::type() const {
  return static_cast< ::QueryType >(type_);
}
inline void SnifferQuery::set_type(::QueryType value) {
  assert(::QueryType_IsValid(value));
  set_has_type();
  type_ = value;
}

// optional int32 record_id = 2;
inline bool SnifferQuery::has_record_id() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void SnifferQuery::set_has_record_id() {
  _has_bits_[0] |= 0x00000002u;
}
inline void SnifferQuery::clear_has_record_id() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void SnifferQuery::clear_record_id() {
  record_id_ = 0;
  clear_has_record_id();
}
inline ::google::protobuf::int32 SnifferQuery::record_id() const {
  return record_id_;
}
inline void SnifferQuery::set_record_id(::google::protobuf::int32 value) {
  set_has_record_id();
  record_id_ = value;
}

// -------------------------------------------------------------------

// SnifferResponse_RSSIRecord

// optional bytes mac = 1;
inline bool SnifferResponse_RSSIRecord::has_mac() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void SnifferResponse_RSSIRecord::set_has_mac() {
  _has_bits_[0] |= 0x00000001u;
}
inline void SnifferResponse_RSSIRecord::clear_has_mac() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void SnifferResponse_RSSIRecord::clear_mac() {
  if (mac_ != &::google::protobuf::internal::kEmptyString) {
    mac_->clear();
  }
  clear_has_mac();
}
inline const ::std::string& SnifferResponse_RSSIRecord::mac() const {
  return *mac_;
}
inline void SnifferResponse_RSSIRecord::set_mac(const ::std::string& value) {
  set_has_mac();
  if (mac_ == &::google::protobuf::internal::kEmptyString) {
    mac_ = new ::std::string;
  }
  mac_->assign(value);
}
inline void SnifferResponse_RSSIRecord::set_mac(const char* value) {
  set_has_mac();
  if (mac_ == &::google::protobuf::internal::kEmptyString) {
    mac_ = new ::std::string;
  }
  mac_->assign(value);
}
inline void SnifferResponse_RSSIRecord::set_mac(const void* value, size_t size) {
  set_has_mac();
  if (mac_ == &::google::protobuf::internal::kEmptyString) {
    mac_ = new ::std::string;
  }
  mac_->assign(reinterpret_cast<const char*>(value), size);
}
inline ::std::string* SnifferResponse_RSSIRecord::mutable_mac() {
  set_has_mac();
  if (mac_ == &::google::protobuf::internal::kEmptyString) {
    mac_ = new ::std::string;
  }
  return mac_;
}
inline ::std::string* SnifferResponse_RSSIRecord::release_mac() {
  clear_has_mac();
  if (mac_ == &::google::protobuf::internal::kEmptyString) {
    return NULL;
  } else {
    ::std::string* temp = mac_;
    mac_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
    return temp;
  }
}
inline void SnifferResponse_RSSIRecord::set_allocated_mac(::std::string* mac) {
  if (mac_ != &::google::protobuf::internal::kEmptyString) {
    delete mac_;
  }
  if (mac) {
    set_has_mac();
    mac_ = mac;
  } else {
    clear_has_mac();
    mac_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  }
}

// optional int32 rssi = 2;
inline bool SnifferResponse_RSSIRecord::has_rssi() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void SnifferResponse_RSSIRecord::set_has_rssi() {
  _has_bits_[0] |= 0x00000002u;
}
inline void SnifferResponse_RSSIRecord::clear_has_rssi() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void SnifferResponse_RSSIRecord::clear_rssi() {
  rssi_ = 0;
  clear_has_rssi();
}
inline ::google::protobuf::int32 SnifferResponse_RSSIRecord::rssi() const {
  return rssi_;
}
inline void SnifferResponse_RSSIRecord::set_rssi(::google::protobuf::int32 value) {
  set_has_rssi();
  rssi_ = value;
}

// optional int32 id = 3;
inline bool SnifferResponse_RSSIRecord::has_id() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void SnifferResponse_RSSIRecord::set_has_id() {
  _has_bits_[0] |= 0x00000004u;
}
inline void SnifferResponse_RSSIRecord::clear_has_id() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void SnifferResponse_RSSIRecord::clear_id() {
  id_ = 0;
  clear_has_id();
}
inline ::google::protobuf::int32 SnifferResponse_RSSIRecord::id() const {
  return id_;
}
inline void SnifferResponse_RSSIRecord::set_id(::google::protobuf::int32 value) {
  set_has_id();
  id_ = value;
}

// -------------------------------------------------------------------

// SnifferResponse

// required .ResponseType type = 1 [default = DATA];
inline bool SnifferResponse::has_type() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void SnifferResponse::set_has_type() {
  _has_bits_[0] |= 0x00000001u;
}
inline void SnifferResponse::clear_has_type() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void SnifferResponse::clear_type() {
  type_ = 0;
  clear_has_type();
}
inline ::ResponseType SnifferResponse::type() const {
  return static_cast< ::ResponseType >(type_);
}
inline void SnifferResponse::set_type(::ResponseType value) {
  assert(::ResponseType_IsValid(value));
  set_has_type();
  type_ = value;
}

// optional bool interrupted = 2;
inline bool SnifferResponse::has_interrupted() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void SnifferResponse::set_has_interrupted() {
  _has_bits_[0] |= 0x00000002u;
}
inline void SnifferResponse::clear_has_interrupted() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void SnifferResponse::clear_interrupted() {
  interrupted_ = false;
  clear_has_interrupted();
}
inline bool SnifferResponse::interrupted() const {
  return interrupted_;
}
inline void SnifferResponse::set_interrupted(bool value) {
  set_has_interrupted();
  interrupted_ = value;
}

// repeated .SnifferResponse.RSSIRecord rssi_data = 3;
inline int SnifferResponse::rssi_data_size() const {
  return rssi_data_.size();
}
inline void SnifferResponse::clear_rssi_data() {
  rssi_data_.Clear();
}
inline const ::SnifferResponse_RSSIRecord& SnifferResponse::rssi_data(int index) const {
  return rssi_data_.Get(index);
}
inline ::SnifferResponse_RSSIRecord* SnifferResponse::mutable_rssi_data(int index) {
  return rssi_data_.Mutable(index);
}
inline ::SnifferResponse_RSSIRecord* SnifferResponse::add_rssi_data() {
  return rssi_data_.Add();
}
inline const ::google::protobuf::RepeatedPtrField< ::SnifferResponse_RSSIRecord >&
SnifferResponse::rssi_data() const {
  return rssi_data_;
}
inline ::google::protobuf::RepeatedPtrField< ::SnifferResponse_RSSIRecord >*
SnifferResponse::mutable_rssi_data() {
  return &rssi_data_;
}

// optional .SnifferStatus status = 4;
inline bool SnifferResponse::has_status() const {
  return (_has_bits_[0] & 0x00000008u) != 0;
}
inline void SnifferResponse::set_has_status() {
  _has_bits_[0] |= 0x00000008u;
}
inline void SnifferResponse::clear_has_status() {
  _has_bits_[0] &= ~0x00000008u;
}
inline void SnifferResponse::clear_status() {
  status_ = 0;
  clear_has_status();
}
inline ::SnifferStatus SnifferResponse::status() const {
  return static_cast< ::SnifferStatus >(status_);
}
inline void SnifferResponse::set_status(::SnifferStatus value) {
  assert(::SnifferStatus_IsValid(value));
  set_has_status();
  status_ = value;
}


// @@protoc_insertion_point(namespace_scope)

#ifndef SWIG
namespace google {
namespace protobuf {

template <>
inline const EnumDescriptor* GetEnumDescriptor< ::QueryType>() {
  return ::QueryType_descriptor();
}
template <>
inline const EnumDescriptor* GetEnumDescriptor< ::ResponseType>() {
  return ::ResponseType_descriptor();
}
template <>
inline const EnumDescriptor* GetEnumDescriptor< ::SnifferStatus>() {
  return ::SnifferStatus_descriptor();
}

}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_sniffer_2eproto__INCLUDED
