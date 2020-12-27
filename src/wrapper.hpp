#pragma once
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <new>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace rust {
inline namespace cxxbridge1 {
// #include "rust/cxx.h"

#ifndef CXXBRIDGE1_PANIC
#define CXXBRIDGE1_PANIC
template <typename Exception>
void panic [[noreturn]] (const char *msg);
#endif // CXXBRIDGE1_PANIC

struct unsafe_bitcopy_t;

namespace {
template <typename T>
class impl;
} // namespace

#ifndef CXXBRIDGE1_RUST_STRING
#define CXXBRIDGE1_RUST_STRING
class String final {
public:
  String() noexcept;
  String(const String &) noexcept;
  String(String &&) noexcept;
  ~String() noexcept;

  String(const std::string &);
  String(const char *);
  String(const char *, std::size_t);

  String &operator=(const String &) noexcept;
  String &operator=(String &&) noexcept;

  explicit operator std::string() const;

  const char *data() const noexcept;
  std::size_t size() const noexcept;
  std::size_t length() const noexcept;

  const char *c_str() noexcept;

  using iterator = char *;
  iterator begin() noexcept;
  iterator end() noexcept;

  using const_iterator = const char *;
  const_iterator begin() const noexcept;
  const_iterator end() const noexcept;
  const_iterator cbegin() const noexcept;
  const_iterator cend() const noexcept;

  bool operator==(const String &) const noexcept;
  bool operator!=(const String &) const noexcept;
  bool operator<(const String &) const noexcept;
  bool operator<=(const String &) const noexcept;
  bool operator>(const String &) const noexcept;
  bool operator>=(const String &) const noexcept;

  String(unsafe_bitcopy_t, const String &) noexcept;

private:
  std::array<std::uintptr_t, 3> repr;
};
#endif // CXXBRIDGE1_RUST_STRING

#ifndef CXXBRIDGE1_RUST_STR
#define CXXBRIDGE1_RUST_STR
class Str final {
public:
  Str() noexcept;
  Str(const String &) noexcept;
  Str(const std::string &);
  Str(const char *);
  Str(const char *, std::size_t);

  Str &operator=(const Str &) noexcept = default;

  explicit operator std::string() const;

  const char *data() const noexcept;
  std::size_t size() const noexcept;
  std::size_t length() const noexcept;

  Str(const Str &) noexcept = default;
  ~Str() noexcept = default;

  using iterator = const char *;
  using const_iterator = const char *;
  const_iterator begin() const noexcept;
  const_iterator end() const noexcept;
  const_iterator cbegin() const noexcept;
  const_iterator cend() const noexcept;

  bool operator==(const Str &) const noexcept;
  bool operator!=(const Str &) const noexcept;
  bool operator<(const Str &) const noexcept;
  bool operator<=(const Str &) const noexcept;
  bool operator>(const Str &) const noexcept;
  bool operator>=(const Str &) const noexcept;

private:
  friend impl<Str>;
  const char *ptr;
  std::size_t len;
};

inline const char *Str::data() const noexcept { return this->ptr; }

inline std::size_t Str::size() const noexcept { return this->len; }

inline std::size_t Str::length() const noexcept { return this->len; }
#endif // CXXBRIDGE1_RUST_STR

#ifndef CXXBRIDGE1_RUST_BOX
#define CXXBRIDGE1_RUST_BOX
template <typename T>
class Box final {
public:
  using value_type = T;
  using const_pointer =
      typename std::add_pointer<typename std::add_const<T>::type>::type;
  using pointer = typename std::add_pointer<T>::type;

  Box() = delete;
  Box(const Box &);
  Box(Box &&) noexcept;
  ~Box() noexcept;

  explicit Box(const T &);
  explicit Box(T &&);

  Box &operator=(const Box &);
  Box &operator=(Box &&) noexcept;

  const T *operator->() const noexcept;
  const T &operator*() const noexcept;
  T *operator->() noexcept;
  T &operator*() noexcept;

  template <typename... Fields>
  static Box in_place(Fields &&...);

  static Box from_raw(T *) noexcept;

  T *into_raw() noexcept;

private:
  class uninit;
  class allocation;
  Box(uninit) noexcept;
  void drop() noexcept;
  T *ptr;
};

template <typename T>
class Box<T>::uninit {};

template <typename T>
class Box<T>::allocation {
  static T *alloc() noexcept;
  static void dealloc(T *) noexcept;

public:
  allocation() noexcept : ptr(alloc()) {}
  ~allocation() noexcept {
    if (this->ptr) {
      dealloc(this->ptr);
    }
  }
  T *ptr;
};

template <typename T>
Box<T>::Box(const Box &other) : Box(*other) {}

template <typename T>
Box<T>::Box(Box &&other) noexcept : ptr(other.ptr) {
  other.ptr = nullptr;
}

template <typename T>
Box<T>::Box(const T &val) {
  allocation alloc;
  ::new (alloc.ptr) T(val);
  this->ptr = alloc.ptr;
  alloc.ptr = nullptr;
}

template <typename T>
Box<T>::Box(T &&val) {
  allocation alloc;
  ::new (alloc.ptr) T(std::move(val));
  this->ptr = alloc.ptr;
  alloc.ptr = nullptr;
}

template <typename T>
Box<T>::~Box() noexcept {
  if (this->ptr) {
    this->drop();
  }
}

template <typename T>
Box<T> &Box<T>::operator=(const Box &other) {
  if (this->ptr) {
    **this = *other;
  } else {
    allocation alloc;
    ::new (alloc.ptr) T(*other);
    this->ptr = alloc.ptr;
    alloc.ptr = nullptr;
  }
  return *this;
}

template <typename T>
Box<T> &Box<T>::operator=(Box &&other) noexcept {
  if (this->ptr) {
    this->drop();
  }
  this->ptr = other.ptr;
  other.ptr = nullptr;
  return *this;
}

template <typename T>
const T *Box<T>::operator->() const noexcept {
  return this->ptr;
}

template <typename T>
const T &Box<T>::operator*() const noexcept {
  return *this->ptr;
}

template <typename T>
T *Box<T>::operator->() noexcept {
  return this->ptr;
}

template <typename T>
T &Box<T>::operator*() noexcept {
  return *this->ptr;
}

template <typename T>
template <typename... Fields>
Box<T> Box<T>::in_place(Fields &&... fields) {
  allocation alloc;
  auto ptr = alloc.ptr;
  ::new (ptr) T{std::forward<Fields>(fields)...};
  alloc.ptr = nullptr;
  return from_raw(ptr);
}

template <typename T>
Box<T> Box<T>::from_raw(T *raw) noexcept {
  Box box = uninit{};
  box.ptr = raw;
  return box;
}

template <typename T>
T *Box<T>::into_raw() noexcept {
  T *raw = this->ptr;
  this->ptr = nullptr;
  return raw;
}

template <typename T>
Box<T>::Box(uninit) noexcept {}
#endif // CXXBRIDGE1_RUST_BOX

#ifndef CXXBRIDGE1_RUST_BITCOPY
#define CXXBRIDGE1_RUST_BITCOPY
struct unsafe_bitcopy_t final {
  explicit unsafe_bitcopy_t() = default;
};

constexpr unsafe_bitcopy_t unsafe_bitcopy{};
#endif // CXXBRIDGE1_RUST_BITCOPY

#ifndef CXXBRIDGE1_RUST_VEC
#define CXXBRIDGE1_RUST_VEC
template <typename T>
class Vec final {
public:
  using value_type = T;

  Vec() noexcept;
  Vec(std::initializer_list<T>);
  Vec(const Vec &);
  Vec(Vec &&) noexcept;
  ~Vec() noexcept;

  Vec &operator=(Vec &&) noexcept;
  Vec &operator=(const Vec &);

  std::size_t size() const noexcept;
  bool empty() const noexcept;
  const T *data() const noexcept;
  T *data() noexcept;
  std::size_t capacity() const noexcept;

  const T &operator[](std::size_t n) const noexcept;
  const T &at(std::size_t n) const;
  const T &front() const noexcept;
  const T &back() const noexcept;

  T &operator[](std::size_t n) noexcept;
  T &at(std::size_t n);
  T &front() noexcept;
  T &back() noexcept;

  void reserve(std::size_t new_cap);
  void push_back(const T &value);
  void push_back(T &&value);
  template <typename... Args>
  void emplace_back(Args &&... args);

  class iterator;
  iterator begin() noexcept;
  iterator end() noexcept;

  using const_iterator = typename Vec<const T>::iterator;
  const_iterator begin() const noexcept;
  const_iterator end() const noexcept;
  const_iterator cbegin() const noexcept;
  const_iterator cend() const noexcept;

  Vec(unsafe_bitcopy_t, const Vec &) noexcept;

private:
  static std::size_t stride() noexcept;
  void reserve_total(std::size_t cap) noexcept;
  void set_len(std::size_t len) noexcept;
  void drop() noexcept;

  std::array<std::uintptr_t, 3> repr;
};

template <typename T>
class Vec<T>::iterator final {
public:
  using iterator_category = std::random_access_iterator_tag;
  using value_type = T;
  using difference_type = std::ptrdiff_t;
  using pointer = typename std::add_pointer<T>::type;
  using reference = typename std::add_lvalue_reference<T>::type;

  reference operator*() const noexcept;
  pointer operator->() const noexcept;
  reference operator[](difference_type) const noexcept;

  iterator &operator++() noexcept;
  iterator operator++(int) noexcept;
  iterator &operator--() noexcept;
  iterator operator--(int) noexcept;

  iterator &operator+=(difference_type) noexcept;
  iterator &operator-=(difference_type) noexcept;
  iterator operator+(difference_type) const noexcept;
  iterator operator-(difference_type) const noexcept;
  difference_type operator-(const iterator &) const noexcept;

  bool operator==(const iterator &) const noexcept;
  bool operator!=(const iterator &) const noexcept;
  bool operator<(const iterator &) const noexcept;
  bool operator>(const iterator &) const noexcept;
  bool operator<=(const iterator &) const noexcept;
  bool operator>=(const iterator &) const noexcept;

private:
  friend class Vec;
  friend class Vec<typename std::remove_const<T>::type>;
  void *pos;
  std::size_t stride;
};

template <typename T>
Vec<T>::Vec(std::initializer_list<T> init) : Vec{} {
  this->reserve_total(init.size());
  std::move(init.begin(), init.end(), std::back_inserter(*this));
}

template <typename T>
Vec<T>::Vec(const Vec &other) : Vec() {
  this->reserve_total(other.size());
  std::copy(other.begin(), other.end(), std::back_inserter(*this));
}

template <typename T>
Vec<T>::Vec(Vec &&other) noexcept : repr(other.repr) {
  new (&other) Vec();
}

template <typename T>
Vec<T>::~Vec() noexcept {
  this->drop();
}

template <typename T>
Vec<T> &Vec<T>::operator=(Vec &&other) noexcept {
  if (this != &other) {
    this->drop();
    this->repr = other.repr;
    new (&other) Vec();
  }
  return *this;
}

template <typename T>
Vec<T> &Vec<T>::operator=(const Vec &other) {
  if (this != &other) {
    this->drop();
    new (this) Vec(other);
  }
  return *this;
}

template <typename T>
bool Vec<T>::empty() const noexcept {
  return this->size() == 0;
}

template <typename T>
T *Vec<T>::data() noexcept {
  return const_cast<T *>(const_cast<const Vec<T> *>(this)->data());
}

template <typename T>
const T &Vec<T>::operator[](std::size_t n) const noexcept {
  assert(n < this->size());
  auto data = reinterpret_cast<const char *>(this->data());
  return *reinterpret_cast<const T *>(data + n * this->stride());
}

template <typename T>
const T &Vec<T>::at(std::size_t n) const {
  if (n >= this->size()) {
    panic<std::out_of_range>("rust::Vec index out of range");
  }
  return (*this)[n];
}

template <typename T>
const T &Vec<T>::front() const noexcept {
  assert(!this->empty());
  return (*this)[0];
}

template <typename T>
const T &Vec<T>::back() const noexcept {
  assert(!this->empty());
  return (*this)[this->size() - 1];
}

template <typename T>
T &Vec<T>::operator[](std::size_t n) noexcept {
  assert(n < this->size());
  auto data = reinterpret_cast<char *>(this->data());
  return *reinterpret_cast<T *>(data + n * this->stride());
}

template <typename T>
T &Vec<T>::at(std::size_t n) {
  if (n >= this->size()) {
    panic<std::out_of_range>("rust::Vec index out of range");
  }
  return (*this)[n];
}

template <typename T>
T &Vec<T>::front() noexcept {
  assert(!this->empty());
  return (*this)[0];
}

template <typename T>
T &Vec<T>::back() noexcept {
  assert(!this->empty());
  return (*this)[this->size() - 1];
}

template <typename T>
void Vec<T>::reserve(std::size_t new_cap) {
  this->reserve_total(new_cap);
}

template <typename T>
void Vec<T>::push_back(const T &value) {
  this->emplace_back(value);
}

template <typename T>
void Vec<T>::push_back(T &&value) {
  this->emplace_back(std::move(value));
}

template <typename T>
template <typename... Args>
void Vec<T>::emplace_back(Args &&... args) {
  auto size = this->size();
  this->reserve_total(size + 1);
  ::new (reinterpret_cast<T *>(reinterpret_cast<char *>(this->data()) +
                               size * this->stride()))
      T(std::forward<Args>(args)...);
  this->set_len(size + 1);
}

template <typename T>
typename Vec<T>::iterator::reference
Vec<T>::iterator::operator*() const noexcept {
  return *static_cast<T *>(this->pos);
}

template <typename T>
typename Vec<T>::iterator::pointer
Vec<T>::iterator::operator->() const noexcept {
  return static_cast<T *>(this->pos);
}

template <typename T>
typename Vec<T>::iterator::reference Vec<T>::iterator::operator[](
    typename Vec<T>::iterator::difference_type n) const noexcept {
  auto pos = static_cast<char *>(this->pos) + this->stride * n;
  return *static_cast<T *>(pos);
}

template <typename T>
typename Vec<T>::iterator &Vec<T>::iterator::operator++() noexcept {
  this->pos = static_cast<char *>(this->pos) + this->stride;
  return *this;
}

template <typename T>
typename Vec<T>::iterator Vec<T>::iterator::operator++(int) noexcept {
  auto ret = iterator(*this);
  this->pos = static_cast<char *>(this->pos) + this->stride;
  return ret;
}

template <typename T>
typename Vec<T>::iterator &Vec<T>::iterator::operator--() noexcept {
  this->pos = static_cast<char *>(this->pos) - this->stride;
  return *this;
}

template <typename T>
typename Vec<T>::iterator Vec<T>::iterator::operator--(int) noexcept {
  auto ret = iterator(*this);
  this->pos = static_cast<char *>(this->pos) - this->stride;
  return ret;
}

template <typename T>
typename Vec<T>::iterator &Vec<T>::iterator::operator+=(
    typename Vec<T>::iterator::difference_type n) noexcept {
  this->pos = static_cast<char *>(this->pos) + this->stride * n;
  return *this;
}

template <typename T>
typename Vec<T>::iterator &Vec<T>::iterator::operator-=(
    typename Vec<T>::iterator::difference_type n) noexcept {
  this->pos = static_cast<char *>(this->pos) - this->stride * n;
  return *this;
}

template <typename T>
typename Vec<T>::iterator Vec<T>::iterator::operator+(
    typename Vec<T>::iterator::difference_type n) const noexcept {
  auto ret = iterator(*this);
  ret.pos = static_cast<char *>(this->pos) + this->stride * n;
  return ret;
}

template <typename T>
typename Vec<T>::iterator Vec<T>::iterator::operator-(
    typename Vec<T>::iterator::difference_type n) const noexcept {
  auto ret = iterator(*this);
  ret.pos = static_cast<char *>(this->pos) - this->stride * n;
  return ret;
}

template <typename T>
typename Vec<T>::iterator::difference_type
Vec<T>::iterator::operator-(const iterator &other) const noexcept {
  auto diff = std::distance(static_cast<char *>(other.pos),
                            static_cast<char *>(this->pos));
  return diff / this->stride;
}

template <typename T>
bool Vec<T>::iterator::operator==(const iterator &other) const noexcept {
  return this->pos == other.pos;
}

template <typename T>
bool Vec<T>::iterator::operator!=(const iterator &other) const noexcept {
  return this->pos != other.pos;
}

template <typename T>
bool Vec<T>::iterator::operator>(const iterator &other) const noexcept {
  return this->pos > other.pos;
}

template <typename T>
bool Vec<T>::iterator::operator<(const iterator &other) const noexcept {
  return this->pos < other.pos;
}

template <typename T>
bool Vec<T>::iterator::operator>=(const iterator &other) const noexcept {
  return this->pos >= other.pos;
}

template <typename T>
bool Vec<T>::iterator::operator<=(const iterator &other) const noexcept {
  return this->pos <= other.pos;
}

template <typename T>
typename Vec<T>::iterator Vec<T>::begin() noexcept {
  iterator it;
  it.pos = const_cast<typename std::remove_const<T>::type *>(this->data());
  it.stride = this->stride();
  return it;
}

template <typename T>
typename Vec<T>::iterator Vec<T>::end() noexcept {
  iterator it = this->begin();
  it.pos = static_cast<char *>(it.pos) + it.stride * this->size();
  return it;
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::begin() const noexcept {
  return this->cbegin();
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::end() const noexcept {
  return this->cend();
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::cbegin() const noexcept {
  const_iterator it;
  it.pos = const_cast<typename std::remove_const<T>::type *>(this->data());
  it.stride = this->stride();
  return it;
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::cend() const noexcept {
  const_iterator it = this->cbegin();
  it.pos = static_cast<char *>(it.pos) + it.stride * this->size();
  return it;
}

template <typename T>
Vec<T>::Vec(unsafe_bitcopy_t, const Vec &bits) noexcept : repr(bits.repr) {}
#endif // CXXBRIDGE1_RUST_VEC

#ifndef CXXBRIDGE1_RUST_OPAQUE
#define CXXBRIDGE1_RUST_OPAQUE
class Opaque {
public:
  Opaque() = delete;
  Opaque(const Opaque &) = delete;
  ~Opaque() = delete;
};
#endif // CXXBRIDGE1_RUST_OPAQUE
} // namespace cxxbridge1
} // namespace rust

namespace challenge_bypass_ristretto {
  struct Error;
  enum class TokenError : ::std::uint8_t;
  struct TokenPreimage;
  struct Token;
  struct BlindedToken;
  struct SignedToken;
  struct UnblindedToken;
  struct SigningKey;
  struct PublicKey;
  struct VerificationKey;
  struct VerificationSignature;
  struct BatchDLEQProof;
  struct Tokens;
  struct BlindedTokens;
  struct SignedTokens;
  struct UnblindedTokens;
  struct TokenPreimageResult;
  struct TokenResult;
  struct BlindedTokenResult;
  struct SignedTokenResult;
  struct UnblindedTokenResult;
  struct SigningKeyResult;
  struct PublicKeyResult;
  struct VerificationSignatureResult;
  struct BatchDLEQProofResult;
  struct TokensResult;
  struct BlindedTokensResult;
  struct SignedTokensResult;
  struct UnblindedTokensResult;
}

namespace challenge_bypass_ristretto {
#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$Error
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$Error
struct Error final {
  ::challenge_bypass_ristretto::TokenError code;
  ::rust::String msg;

  bool is_ok() const noexcept;
  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$Error

#ifndef CXXBRIDGE1_ENUM_challenge_bypass_ristretto$TokenError
#define CXXBRIDGE1_ENUM_challenge_bypass_ristretto$TokenError
enum class TokenError : ::std::uint8_t {
  None = 0,
  PointDecompressionError = 1,
  ScalarFormatError = 2,
  BytesLengthError = 3,
  VerifyError = 4,
  LengthMismatchError = 5,
  DecodingError = 6,
};
#endif // CXXBRIDGE1_ENUM_challenge_bypass_ristretto$TokenError

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenPreimage
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenPreimage
struct TokenPreimage final : public ::rust::Opaque {
  ::rust::String encode_base64() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenPreimage

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$Token
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$Token
struct Token final : public ::rust::Opaque {
  ::rust::String encode_base64() const noexcept;
  ::rust::Box<::challenge_bypass_ristretto::BlindedToken> blind() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$Token

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedToken
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedToken
struct BlindedToken final : public ::rust::Opaque {
  ::rust::String encode_base64() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedToken

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedToken
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedToken
struct SignedToken final : public ::rust::Opaque {
  ::rust::String encode_base64() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedToken

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedToken
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedToken
struct UnblindedToken final : public ::rust::Opaque {
  ::rust::String encode_base64() const noexcept;
  ::rust::Box<::challenge_bypass_ristretto::VerificationKey> derive_verification_key() const noexcept;
  const ::challenge_bypass_ristretto::TokenPreimage &preimage() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedToken

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SigningKey
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SigningKey
struct SigningKey final : public ::rust::Opaque {
  ::rust::String encode_base64() const noexcept;
  ::rust::Box<::challenge_bypass_ristretto::PublicKey> public_key() const noexcept;
  ::rust::Box<::challenge_bypass_ristretto::SignedTokenResult> sign(const ::challenge_bypass_ristretto::BlindedToken &token) const noexcept;
  ::rust::Box<::challenge_bypass_ristretto::UnblindedToken> rederive_unblinded_token(const ::challenge_bypass_ristretto::TokenPreimage &t) const noexcept;
  ::rust::Box<::challenge_bypass_ristretto::BatchDLEQProofResult> new_batch_dleq_proof(const ::challenge_bypass_ristretto::BlindedTokens &blinded_tokens, const ::challenge_bypass_ristretto::SignedTokens &signed_tokens) const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SigningKey

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$PublicKey
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$PublicKey
struct PublicKey final : public ::rust::Opaque {
  ::rust::String encode_base64() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$PublicKey

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationKey
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationKey
struct VerificationKey final : public ::rust::Opaque {
  ::rust::Box<::challenge_bypass_ristretto::VerificationSignature> sign(const ::std::string &msg) const noexcept;
  bool verify(const ::challenge_bypass_ristretto::VerificationSignature &sig, const ::std::string &msg) const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationKey

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationSignature
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationSignature
struct VerificationSignature final : public ::rust::Opaque {
  ::rust::String encode_base64() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationSignature

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BatchDLEQProof
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BatchDLEQProof
struct BatchDLEQProof final : public ::rust::Opaque {
  ::rust::String encode_base64() const noexcept;
  ::challenge_bypass_ristretto::Error verify(const ::challenge_bypass_ristretto::BlindedTokens &blinded_tokens, const ::challenge_bypass_ristretto::SignedTokens &signed_tokens, const ::challenge_bypass_ristretto::PublicKey &public_key) const noexcept;
  ::rust::Box<::challenge_bypass_ristretto::UnblindedTokensResult> verify_and_unblind(const ::challenge_bypass_ristretto::Tokens &tokens, const ::challenge_bypass_ristretto::BlindedTokens &blinded_tokens, const ::challenge_bypass_ristretto::SignedTokens &signed_tokens, const ::challenge_bypass_ristretto::PublicKey &public_key) const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BatchDLEQProof

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokens
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokens
struct UnblindedTokens final : public ::rust::Opaque {
  const ::rust::Vec<::challenge_bypass_ristretto::UnblindedToken> &as_vec() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokens

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenPreimageResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenPreimageResult
struct TokenPreimageResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::TokenPreimage &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenPreimageResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenResult
struct TokenResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::Token &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokenResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokenResult
struct BlindedTokenResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::BlindedToken &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokenResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokenResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokenResult
struct SignedTokenResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::SignedToken &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokenResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokenResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokenResult
struct UnblindedTokenResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::UnblindedToken &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokenResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SigningKeyResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SigningKeyResult
struct SigningKeyResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::SigningKey &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SigningKeyResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$PublicKeyResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$PublicKeyResult
struct PublicKeyResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::PublicKey &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$PublicKeyResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationSignatureResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationSignatureResult
struct VerificationSignatureResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::VerificationSignature &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationSignatureResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BatchDLEQProofResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BatchDLEQProofResult
struct BatchDLEQProofResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::BatchDLEQProof &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BatchDLEQProofResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokensResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokensResult
struct TokensResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::Tokens &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokensResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokensResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokensResult
struct BlindedTokensResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::BlindedTokens &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokensResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokensResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokensResult
struct SignedTokensResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::SignedTokens &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokensResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokensResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokensResult
struct UnblindedTokensResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  bool is_ok() const noexcept;
  const ::challenge_bypass_ristretto::UnblindedTokens &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokensResult

::rust::Box<::challenge_bypass_ristretto::TokenPreimageResult> decode_base64_token_preimage(::rust::Str s) noexcept;

::rust::Box<::challenge_bypass_ristretto::Token> generate_token() noexcept;

::rust::Box<::challenge_bypass_ristretto::TokenResult> decode_base64_token(::rust::Str s) noexcept;

::rust::Box<::challenge_bypass_ristretto::BlindedTokenResult> decode_base64_blinded_token(::rust::Str s) noexcept;

::rust::Box<::challenge_bypass_ristretto::SignedTokenResult> decode_base64_signed_token(::rust::Str s) noexcept;

::rust::Box<::challenge_bypass_ristretto::UnblindedTokenResult> decode_base64_unblinded_token(::rust::Str s) noexcept;

::rust::Box<::challenge_bypass_ristretto::SigningKey> generate_signing_key() noexcept;

::rust::Box<::challenge_bypass_ristretto::SigningKeyResult> decode_base64_signing_key(::rust::Str s) noexcept;

::rust::Box<::challenge_bypass_ristretto::PublicKeyResult> decode_base64_public_key(::rust::Str s) noexcept;

::rust::Box<::challenge_bypass_ristretto::VerificationSignatureResult> decode_base64_verification_signature(::rust::Str s) noexcept;

::rust::Box<::challenge_bypass_ristretto::BatchDLEQProofResult> decode_base64_batch_dleq_proof(::rust::Str s) noexcept;

::rust::Box<::challenge_bypass_ristretto::TokensResult> decode_base64_tokens(const ::std::vector<::std::string> &s) noexcept;

::rust::Box<::challenge_bypass_ristretto::BlindedTokensResult> decode_base64_blinded_tokens(const ::std::vector<::std::string> &s) noexcept;

::rust::Box<::challenge_bypass_ristretto::SignedTokensResult> decode_base64_signed_tokens(const ::std::vector<::std::string> &s) noexcept;

::rust::Box<::challenge_bypass_ristretto::UnblindedTokensResult> decode_base64_unblinded_tokens(const ::std::vector<::std::string> &s) noexcept;
} // namespace challenge_bypass_ristretto
