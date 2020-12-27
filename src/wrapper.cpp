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

namespace detail {
template <typename T, typename = void *>
struct operator_new {
  void *operator()(::std::size_t sz) { return ::operator new(sz); }
};

template <typename T>
struct operator_new<T, decltype(T::operator new(sizeof(T)))> {
  void *operator()(::std::size_t sz) { return T::operator new(sz); }
};
} // namespace detail

template <typename T>
union MaybeUninit {
  T value;
  void *operator new(::std::size_t sz) { return detail::operator_new<T>{}(sz); }
  MaybeUninit() {}
  ~MaybeUninit() {}
};

namespace {
namespace repr {
struct PtrLen final {
  void *ptr;
  ::std::size_t len;
};
} // namespace repr

template <>
class impl<Str> final {
public:
  static repr::PtrLen repr(Str str) noexcept {
    return repr::PtrLen{const_cast<char *>(str.ptr), str.len};
  }
};
} // namespace
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

  bool ok() const noexcept;
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
  const ::challenge_bypass_ristretto::TokenPreimage &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenPreimageResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenResult
struct TokenResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::Token &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokenResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokenResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokenResult
struct BlindedTokenResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::BlindedToken &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokenResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokenResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokenResult
struct SignedTokenResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::SignedToken &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokenResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokenResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokenResult
struct UnblindedTokenResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::UnblindedToken &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokenResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SigningKeyResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SigningKeyResult
struct SigningKeyResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::SigningKey &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SigningKeyResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$PublicKeyResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$PublicKeyResult
struct PublicKeyResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::PublicKey &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$PublicKeyResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationSignatureResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationSignatureResult
struct VerificationSignatureResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::VerificationSignature &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$VerificationSignatureResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BatchDLEQProofResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BatchDLEQProofResult
struct BatchDLEQProofResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::BatchDLEQProof &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BatchDLEQProofResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokensResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokensResult
struct TokensResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::Tokens &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$TokensResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokensResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokensResult
struct BlindedTokensResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::BlindedTokens &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$BlindedTokensResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokensResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokensResult
struct SignedTokensResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::SignedTokens &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$SignedTokensResult

#ifndef CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokensResult
#define CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokensResult
struct UnblindedTokensResult final : public ::rust::Opaque {
  const ::challenge_bypass_ristretto::Error &error() const noexcept;
  const ::challenge_bypass_ristretto::UnblindedTokens &unwrap() const noexcept;
};
#endif // CXXBRIDGE1_STRUCT_challenge_bypass_ristretto$UnblindedTokensResult

extern "C" {
bool challenge_bypass_ristretto$cxxbridge1$Error$ok(const ::challenge_bypass_ristretto::Error &self) noexcept;

void challenge_bypass_ristretto$cxxbridge1$TokenPreimage$encode_base64(const ::challenge_bypass_ristretto::TokenPreimage &self, ::rust::String *return$) noexcept;

::challenge_bypass_ristretto::TokenPreimageResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_token_preimage(::rust::repr::PtrLen s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$TokenPreimageResult$error(const ::challenge_bypass_ristretto::TokenPreimageResult &self) noexcept;

const ::challenge_bypass_ristretto::TokenPreimage *challenge_bypass_ristretto$cxxbridge1$TokenPreimageResult$unwrap(const ::challenge_bypass_ristretto::TokenPreimageResult &self) noexcept;

::challenge_bypass_ristretto::Token *challenge_bypass_ristretto$cxxbridge1$generate_token() noexcept;

void challenge_bypass_ristretto$cxxbridge1$Token$encode_base64(const ::challenge_bypass_ristretto::Token &self, ::rust::String *return$) noexcept;

::challenge_bypass_ristretto::BlindedToken *challenge_bypass_ristretto$cxxbridge1$Token$blind(const ::challenge_bypass_ristretto::Token &self) noexcept;

::challenge_bypass_ristretto::TokenResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_token(::rust::repr::PtrLen s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$TokenResult$error(const ::challenge_bypass_ristretto::TokenResult &self) noexcept;

const ::challenge_bypass_ristretto::Token *challenge_bypass_ristretto$cxxbridge1$TokenResult$unwrap(const ::challenge_bypass_ristretto::TokenResult &self) noexcept;

void challenge_bypass_ristretto$cxxbridge1$BlindedToken$encode_base64(const ::challenge_bypass_ristretto::BlindedToken &self, ::rust::String *return$) noexcept;

::challenge_bypass_ristretto::BlindedTokenResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_blinded_token(::rust::repr::PtrLen s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$BlindedTokenResult$error(const ::challenge_bypass_ristretto::BlindedTokenResult &self) noexcept;

const ::challenge_bypass_ristretto::BlindedToken *challenge_bypass_ristretto$cxxbridge1$BlindedTokenResult$unwrap(const ::challenge_bypass_ristretto::BlindedTokenResult &self) noexcept;

void challenge_bypass_ristretto$cxxbridge1$SignedToken$encode_base64(const ::challenge_bypass_ristretto::SignedToken &self, ::rust::String *return$) noexcept;

::challenge_bypass_ristretto::SignedTokenResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_signed_token(::rust::repr::PtrLen s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$SignedTokenResult$error(const ::challenge_bypass_ristretto::SignedTokenResult &self) noexcept;

const ::challenge_bypass_ristretto::SignedToken *challenge_bypass_ristretto$cxxbridge1$SignedTokenResult$unwrap(const ::challenge_bypass_ristretto::SignedTokenResult &self) noexcept;

void challenge_bypass_ristretto$cxxbridge1$UnblindedToken$encode_base64(const ::challenge_bypass_ristretto::UnblindedToken &self, ::rust::String *return$) noexcept;

::challenge_bypass_ristretto::VerificationKey *challenge_bypass_ristretto$cxxbridge1$UnblindedToken$derive_verification_key(const ::challenge_bypass_ristretto::UnblindedToken &self) noexcept;

const ::challenge_bypass_ristretto::TokenPreimage *challenge_bypass_ristretto$cxxbridge1$UnblindedToken$preimage(const ::challenge_bypass_ristretto::UnblindedToken &self) noexcept;

::challenge_bypass_ristretto::UnblindedTokenResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_unblinded_token(::rust::repr::PtrLen s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$UnblindedTokenResult$error(const ::challenge_bypass_ristretto::UnblindedTokenResult &self) noexcept;

const ::challenge_bypass_ristretto::UnblindedToken *challenge_bypass_ristretto$cxxbridge1$UnblindedTokenResult$unwrap(const ::challenge_bypass_ristretto::UnblindedTokenResult &self) noexcept;

::challenge_bypass_ristretto::SigningKey *challenge_bypass_ristretto$cxxbridge1$generate_signing_key() noexcept;

void challenge_bypass_ristretto$cxxbridge1$SigningKey$encode_base64(const ::challenge_bypass_ristretto::SigningKey &self, ::rust::String *return$) noexcept;

::challenge_bypass_ristretto::PublicKey *challenge_bypass_ristretto$cxxbridge1$SigningKey$public_key(const ::challenge_bypass_ristretto::SigningKey &self) noexcept;

::challenge_bypass_ristretto::SignedTokenResult *challenge_bypass_ristretto$cxxbridge1$SigningKey$sign(const ::challenge_bypass_ristretto::SigningKey &self, const ::challenge_bypass_ristretto::BlindedToken &token) noexcept;

::challenge_bypass_ristretto::UnblindedToken *challenge_bypass_ristretto$cxxbridge1$SigningKey$rederive_unblinded_token(const ::challenge_bypass_ristretto::SigningKey &self, const ::challenge_bypass_ristretto::TokenPreimage &t) noexcept;

::challenge_bypass_ristretto::SigningKeyResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_signing_key(::rust::repr::PtrLen s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$SigningKeyResult$error(const ::challenge_bypass_ristretto::SigningKeyResult &self) noexcept;

const ::challenge_bypass_ristretto::SigningKey *challenge_bypass_ristretto$cxxbridge1$SigningKeyResult$unwrap(const ::challenge_bypass_ristretto::SigningKeyResult &self) noexcept;

void challenge_bypass_ristretto$cxxbridge1$PublicKey$encode_base64(const ::challenge_bypass_ristretto::PublicKey &self, ::rust::String *return$) noexcept;

::challenge_bypass_ristretto::PublicKeyResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_public_key(::rust::repr::PtrLen s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$PublicKeyResult$error(const ::challenge_bypass_ristretto::PublicKeyResult &self) noexcept;

const ::challenge_bypass_ristretto::PublicKey *challenge_bypass_ristretto$cxxbridge1$PublicKeyResult$unwrap(const ::challenge_bypass_ristretto::PublicKeyResult &self) noexcept;

::challenge_bypass_ristretto::VerificationSignature *challenge_bypass_ristretto$cxxbridge1$VerificationKey$sign(const ::challenge_bypass_ristretto::VerificationKey &self, const ::std::string &msg) noexcept;

bool challenge_bypass_ristretto$cxxbridge1$VerificationKey$verify(const ::challenge_bypass_ristretto::VerificationKey &self, const ::challenge_bypass_ristretto::VerificationSignature &sig, const ::std::string &msg) noexcept;

void challenge_bypass_ristretto$cxxbridge1$VerificationSignature$encode_base64(const ::challenge_bypass_ristretto::VerificationSignature &self, ::rust::String *return$) noexcept;

::challenge_bypass_ristretto::VerificationSignatureResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_verification_signature(::rust::repr::PtrLen s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$VerificationSignatureResult$error(const ::challenge_bypass_ristretto::VerificationSignatureResult &self) noexcept;

const ::challenge_bypass_ristretto::VerificationSignature *challenge_bypass_ristretto$cxxbridge1$VerificationSignatureResult$unwrap(const ::challenge_bypass_ristretto::VerificationSignatureResult &self) noexcept;

::challenge_bypass_ristretto::BatchDLEQProofResult *challenge_bypass_ristretto$cxxbridge1$SigningKey$new_batch_dleq_proof(const ::challenge_bypass_ristretto::SigningKey &self, const ::challenge_bypass_ristretto::BlindedTokens &blinded_tokens, const ::challenge_bypass_ristretto::SignedTokens &signed_tokens) noexcept;

void challenge_bypass_ristretto$cxxbridge1$BatchDLEQProof$encode_base64(const ::challenge_bypass_ristretto::BatchDLEQProof &self, ::rust::String *return$) noexcept;

void challenge_bypass_ristretto$cxxbridge1$BatchDLEQProof$verify(const ::challenge_bypass_ristretto::BatchDLEQProof &self, const ::challenge_bypass_ristretto::BlindedTokens &blinded_tokens, const ::challenge_bypass_ristretto::SignedTokens &signed_tokens, const ::challenge_bypass_ristretto::PublicKey &public_key, ::challenge_bypass_ristretto::Error *return$) noexcept;

::challenge_bypass_ristretto::UnblindedTokensResult *challenge_bypass_ristretto$cxxbridge1$BatchDLEQProof$verify_and_unblind(const ::challenge_bypass_ristretto::BatchDLEQProof &self, const ::challenge_bypass_ristretto::Tokens &tokens, const ::challenge_bypass_ristretto::BlindedTokens &blinded_tokens, const ::challenge_bypass_ristretto::SignedTokens &signed_tokens, const ::challenge_bypass_ristretto::PublicKey &public_key) noexcept;

::challenge_bypass_ristretto::BatchDLEQProofResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_batch_dleq_proof(::rust::repr::PtrLen s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$BatchDLEQProofResult$error(const ::challenge_bypass_ristretto::BatchDLEQProofResult &self) noexcept;

const ::challenge_bypass_ristretto::BatchDLEQProof *challenge_bypass_ristretto$cxxbridge1$BatchDLEQProofResult$unwrap(const ::challenge_bypass_ristretto::BatchDLEQProofResult &self) noexcept;

::challenge_bypass_ristretto::TokensResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_tokens(const ::std::vector<::std::string> &s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$TokensResult$error(const ::challenge_bypass_ristretto::TokensResult &self) noexcept;

const ::challenge_bypass_ristretto::Tokens *challenge_bypass_ristretto$cxxbridge1$TokensResult$unwrap(const ::challenge_bypass_ristretto::TokensResult &self) noexcept;

::challenge_bypass_ristretto::BlindedTokensResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_blinded_tokens(const ::std::vector<::std::string> &s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$BlindedTokensResult$error(const ::challenge_bypass_ristretto::BlindedTokensResult &self) noexcept;

const ::challenge_bypass_ristretto::BlindedTokens *challenge_bypass_ristretto$cxxbridge1$BlindedTokensResult$unwrap(const ::challenge_bypass_ristretto::BlindedTokensResult &self) noexcept;

::challenge_bypass_ristretto::SignedTokensResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_signed_tokens(const ::std::vector<::std::string> &s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$SignedTokensResult$error(const ::challenge_bypass_ristretto::SignedTokensResult &self) noexcept;

const ::challenge_bypass_ristretto::SignedTokens *challenge_bypass_ristretto$cxxbridge1$SignedTokensResult$unwrap(const ::challenge_bypass_ristretto::SignedTokensResult &self) noexcept;

::challenge_bypass_ristretto::UnblindedTokensResult *challenge_bypass_ristretto$cxxbridge1$decode_base64_unblinded_tokens(const ::std::vector<::std::string> &s) noexcept;

const ::challenge_bypass_ristretto::Error *challenge_bypass_ristretto$cxxbridge1$UnblindedTokensResult$error(const ::challenge_bypass_ristretto::UnblindedTokensResult &self) noexcept;

const ::challenge_bypass_ristretto::UnblindedTokens *challenge_bypass_ristretto$cxxbridge1$UnblindedTokensResult$unwrap(const ::challenge_bypass_ristretto::UnblindedTokensResult &self) noexcept;

const ::rust::Vec<::challenge_bypass_ristretto::UnblindedToken> *challenge_bypass_ristretto$cxxbridge1$UnblindedTokens$as_vec(const ::challenge_bypass_ristretto::UnblindedTokens &self) noexcept;
} // extern "C"

bool Error::ok() const noexcept {
  return challenge_bypass_ristretto$cxxbridge1$Error$ok(*this);
}

::rust::String TokenPreimage::encode_base64() const noexcept {
  ::rust::MaybeUninit<::rust::String> return$;
  challenge_bypass_ristretto$cxxbridge1$TokenPreimage$encode_base64(*this, &return$.value);
  return ::std::move(return$.value);
}

::rust::Box<::challenge_bypass_ristretto::TokenPreimageResult> decode_base64_token_preimage(::rust::Str s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::TokenPreimageResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_token_preimage(::rust::impl<::rust::Str>::repr(s)));
}

const ::challenge_bypass_ristretto::Error &TokenPreimageResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$TokenPreimageResult$error(*this);
}

const ::challenge_bypass_ristretto::TokenPreimage &TokenPreimageResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$TokenPreimageResult$unwrap(*this);
}

::rust::Box<::challenge_bypass_ristretto::Token> generate_token() noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::Token>::from_raw(challenge_bypass_ristretto$cxxbridge1$generate_token());
}

::rust::String Token::encode_base64() const noexcept {
  ::rust::MaybeUninit<::rust::String> return$;
  challenge_bypass_ristretto$cxxbridge1$Token$encode_base64(*this, &return$.value);
  return ::std::move(return$.value);
}

::rust::Box<::challenge_bypass_ristretto::BlindedToken> Token::blind() const noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::BlindedToken>::from_raw(challenge_bypass_ristretto$cxxbridge1$Token$blind(*this));
}

::rust::Box<::challenge_bypass_ristretto::TokenResult> decode_base64_token(::rust::Str s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::TokenResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_token(::rust::impl<::rust::Str>::repr(s)));
}

const ::challenge_bypass_ristretto::Error &TokenResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$TokenResult$error(*this);
}

const ::challenge_bypass_ristretto::Token &TokenResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$TokenResult$unwrap(*this);
}

::rust::String BlindedToken::encode_base64() const noexcept {
  ::rust::MaybeUninit<::rust::String> return$;
  challenge_bypass_ristretto$cxxbridge1$BlindedToken$encode_base64(*this, &return$.value);
  return ::std::move(return$.value);
}

::rust::Box<::challenge_bypass_ristretto::BlindedTokenResult> decode_base64_blinded_token(::rust::Str s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::BlindedTokenResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_blinded_token(::rust::impl<::rust::Str>::repr(s)));
}

const ::challenge_bypass_ristretto::Error &BlindedTokenResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$BlindedTokenResult$error(*this);
}

const ::challenge_bypass_ristretto::BlindedToken &BlindedTokenResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$BlindedTokenResult$unwrap(*this);
}

::rust::String SignedToken::encode_base64() const noexcept {
  ::rust::MaybeUninit<::rust::String> return$;
  challenge_bypass_ristretto$cxxbridge1$SignedToken$encode_base64(*this, &return$.value);
  return ::std::move(return$.value);
}

::rust::Box<::challenge_bypass_ristretto::SignedTokenResult> decode_base64_signed_token(::rust::Str s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::SignedTokenResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_signed_token(::rust::impl<::rust::Str>::repr(s)));
}

const ::challenge_bypass_ristretto::Error &SignedTokenResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$SignedTokenResult$error(*this);
}

const ::challenge_bypass_ristretto::SignedToken &SignedTokenResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$SignedTokenResult$unwrap(*this);
}

::rust::String UnblindedToken::encode_base64() const noexcept {
  ::rust::MaybeUninit<::rust::String> return$;
  challenge_bypass_ristretto$cxxbridge1$UnblindedToken$encode_base64(*this, &return$.value);
  return ::std::move(return$.value);
}

::rust::Box<::challenge_bypass_ristretto::VerificationKey> UnblindedToken::derive_verification_key() const noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::VerificationKey>::from_raw(challenge_bypass_ristretto$cxxbridge1$UnblindedToken$derive_verification_key(*this));
}

const ::challenge_bypass_ristretto::TokenPreimage &UnblindedToken::preimage() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$UnblindedToken$preimage(*this);
}

::rust::Box<::challenge_bypass_ristretto::UnblindedTokenResult> decode_base64_unblinded_token(::rust::Str s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::UnblindedTokenResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_unblinded_token(::rust::impl<::rust::Str>::repr(s)));
}

const ::challenge_bypass_ristretto::Error &UnblindedTokenResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$UnblindedTokenResult$error(*this);
}

const ::challenge_bypass_ristretto::UnblindedToken &UnblindedTokenResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$UnblindedTokenResult$unwrap(*this);
}

::rust::Box<::challenge_bypass_ristretto::SigningKey> generate_signing_key() noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::SigningKey>::from_raw(challenge_bypass_ristretto$cxxbridge1$generate_signing_key());
}

::rust::String SigningKey::encode_base64() const noexcept {
  ::rust::MaybeUninit<::rust::String> return$;
  challenge_bypass_ristretto$cxxbridge1$SigningKey$encode_base64(*this, &return$.value);
  return ::std::move(return$.value);
}

::rust::Box<::challenge_bypass_ristretto::PublicKey> SigningKey::public_key() const noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::PublicKey>::from_raw(challenge_bypass_ristretto$cxxbridge1$SigningKey$public_key(*this));
}

::rust::Box<::challenge_bypass_ristretto::SignedTokenResult> SigningKey::sign(const ::challenge_bypass_ristretto::BlindedToken &token) const noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::SignedTokenResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$SigningKey$sign(*this, token));
}

::rust::Box<::challenge_bypass_ristretto::UnblindedToken> SigningKey::rederive_unblinded_token(const ::challenge_bypass_ristretto::TokenPreimage &t) const noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::UnblindedToken>::from_raw(challenge_bypass_ristretto$cxxbridge1$SigningKey$rederive_unblinded_token(*this, t));
}

::rust::Box<::challenge_bypass_ristretto::SigningKeyResult> decode_base64_signing_key(::rust::Str s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::SigningKeyResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_signing_key(::rust::impl<::rust::Str>::repr(s)));
}

const ::challenge_bypass_ristretto::Error &SigningKeyResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$SigningKeyResult$error(*this);
}

const ::challenge_bypass_ristretto::SigningKey &SigningKeyResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$SigningKeyResult$unwrap(*this);
}

::rust::String PublicKey::encode_base64() const noexcept {
  ::rust::MaybeUninit<::rust::String> return$;
  challenge_bypass_ristretto$cxxbridge1$PublicKey$encode_base64(*this, &return$.value);
  return ::std::move(return$.value);
}

::rust::Box<::challenge_bypass_ristretto::PublicKeyResult> decode_base64_public_key(::rust::Str s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::PublicKeyResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_public_key(::rust::impl<::rust::Str>::repr(s)));
}

const ::challenge_bypass_ristretto::Error &PublicKeyResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$PublicKeyResult$error(*this);
}

const ::challenge_bypass_ristretto::PublicKey &PublicKeyResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$PublicKeyResult$unwrap(*this);
}

::rust::Box<::challenge_bypass_ristretto::VerificationSignature> VerificationKey::sign(const ::std::string &msg) const noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::VerificationSignature>::from_raw(challenge_bypass_ristretto$cxxbridge1$VerificationKey$sign(*this, msg));
}

bool VerificationKey::verify(const ::challenge_bypass_ristretto::VerificationSignature &sig, const ::std::string &msg) const noexcept {
  return challenge_bypass_ristretto$cxxbridge1$VerificationKey$verify(*this, sig, msg);
}

::rust::String VerificationSignature::encode_base64() const noexcept {
  ::rust::MaybeUninit<::rust::String> return$;
  challenge_bypass_ristretto$cxxbridge1$VerificationSignature$encode_base64(*this, &return$.value);
  return ::std::move(return$.value);
}

::rust::Box<::challenge_bypass_ristretto::VerificationSignatureResult> decode_base64_verification_signature(::rust::Str s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::VerificationSignatureResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_verification_signature(::rust::impl<::rust::Str>::repr(s)));
}

const ::challenge_bypass_ristretto::Error &VerificationSignatureResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$VerificationSignatureResult$error(*this);
}

const ::challenge_bypass_ristretto::VerificationSignature &VerificationSignatureResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$VerificationSignatureResult$unwrap(*this);
}

::rust::Box<::challenge_bypass_ristretto::BatchDLEQProofResult> SigningKey::new_batch_dleq_proof(const ::challenge_bypass_ristretto::BlindedTokens &blinded_tokens, const ::challenge_bypass_ristretto::SignedTokens &signed_tokens) const noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::BatchDLEQProofResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$SigningKey$new_batch_dleq_proof(*this, blinded_tokens, signed_tokens));
}

::rust::String BatchDLEQProof::encode_base64() const noexcept {
  ::rust::MaybeUninit<::rust::String> return$;
  challenge_bypass_ristretto$cxxbridge1$BatchDLEQProof$encode_base64(*this, &return$.value);
  return ::std::move(return$.value);
}

::challenge_bypass_ristretto::Error BatchDLEQProof::verify(const ::challenge_bypass_ristretto::BlindedTokens &blinded_tokens, const ::challenge_bypass_ristretto::SignedTokens &signed_tokens, const ::challenge_bypass_ristretto::PublicKey &public_key) const noexcept {
  ::rust::MaybeUninit<::challenge_bypass_ristretto::Error> return$;
  challenge_bypass_ristretto$cxxbridge1$BatchDLEQProof$verify(*this, blinded_tokens, signed_tokens, public_key, &return$.value);
  return ::std::move(return$.value);
}

::rust::Box<::challenge_bypass_ristretto::UnblindedTokensResult> BatchDLEQProof::verify_and_unblind(const ::challenge_bypass_ristretto::Tokens &tokens, const ::challenge_bypass_ristretto::BlindedTokens &blinded_tokens, const ::challenge_bypass_ristretto::SignedTokens &signed_tokens, const ::challenge_bypass_ristretto::PublicKey &public_key) const noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::UnblindedTokensResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$BatchDLEQProof$verify_and_unblind(*this, tokens, blinded_tokens, signed_tokens, public_key));
}

::rust::Box<::challenge_bypass_ristretto::BatchDLEQProofResult> decode_base64_batch_dleq_proof(::rust::Str s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::BatchDLEQProofResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_batch_dleq_proof(::rust::impl<::rust::Str>::repr(s)));
}

const ::challenge_bypass_ristretto::Error &BatchDLEQProofResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$BatchDLEQProofResult$error(*this);
}

const ::challenge_bypass_ristretto::BatchDLEQProof &BatchDLEQProofResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$BatchDLEQProofResult$unwrap(*this);
}

::rust::Box<::challenge_bypass_ristretto::TokensResult> decode_base64_tokens(const ::std::vector<::std::string> &s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::TokensResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_tokens(s));
}

const ::challenge_bypass_ristretto::Error &TokensResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$TokensResult$error(*this);
}

const ::challenge_bypass_ristretto::Tokens &TokensResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$TokensResult$unwrap(*this);
}

::rust::Box<::challenge_bypass_ristretto::BlindedTokensResult> decode_base64_blinded_tokens(const ::std::vector<::std::string> &s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::BlindedTokensResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_blinded_tokens(s));
}

const ::challenge_bypass_ristretto::Error &BlindedTokensResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$BlindedTokensResult$error(*this);
}

const ::challenge_bypass_ristretto::BlindedTokens &BlindedTokensResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$BlindedTokensResult$unwrap(*this);
}

::rust::Box<::challenge_bypass_ristretto::SignedTokensResult> decode_base64_signed_tokens(const ::std::vector<::std::string> &s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::SignedTokensResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_signed_tokens(s));
}

const ::challenge_bypass_ristretto::Error &SignedTokensResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$SignedTokensResult$error(*this);
}

const ::challenge_bypass_ristretto::SignedTokens &SignedTokensResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$SignedTokensResult$unwrap(*this);
}

::rust::Box<::challenge_bypass_ristretto::UnblindedTokensResult> decode_base64_unblinded_tokens(const ::std::vector<::std::string> &s) noexcept {
  return ::rust::Box<::challenge_bypass_ristretto::UnblindedTokensResult>::from_raw(challenge_bypass_ristretto$cxxbridge1$decode_base64_unblinded_tokens(s));
}

const ::challenge_bypass_ristretto::Error &UnblindedTokensResult::error() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$UnblindedTokensResult$error(*this);
}

const ::challenge_bypass_ristretto::UnblindedTokens &UnblindedTokensResult::unwrap() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$UnblindedTokensResult$unwrap(*this);
}

const ::rust::Vec<::challenge_bypass_ristretto::UnblindedToken> &UnblindedTokens::as_vec() const noexcept {
  return *challenge_bypass_ristretto$cxxbridge1$UnblindedTokens$as_vec(*this);
}
} // namespace challenge_bypass_ristretto

extern "C" {
#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$TokenPreimageResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$TokenPreimageResult
::challenge_bypass_ristretto::TokenPreimageResult *cxxbridge1$box$challenge_bypass_ristretto$TokenPreimageResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$TokenPreimageResult$dealloc(::challenge_bypass_ristretto::TokenPreimageResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$TokenPreimageResult$drop(::rust::Box<::challenge_bypass_ristretto::TokenPreimageResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$TokenPreimageResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$Token
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$Token
::challenge_bypass_ristretto::Token *cxxbridge1$box$challenge_bypass_ristretto$Token$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$Token$dealloc(::challenge_bypass_ristretto::Token *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$Token$drop(::rust::Box<::challenge_bypass_ristretto::Token> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$Token

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BlindedToken
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BlindedToken
::challenge_bypass_ristretto::BlindedToken *cxxbridge1$box$challenge_bypass_ristretto$BlindedToken$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$BlindedToken$dealloc(::challenge_bypass_ristretto::BlindedToken *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$BlindedToken$drop(::rust::Box<::challenge_bypass_ristretto::BlindedToken> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BlindedToken

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$TokenResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$TokenResult
::challenge_bypass_ristretto::TokenResult *cxxbridge1$box$challenge_bypass_ristretto$TokenResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$TokenResult$dealloc(::challenge_bypass_ristretto::TokenResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$TokenResult$drop(::rust::Box<::challenge_bypass_ristretto::TokenResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$TokenResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BlindedTokenResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BlindedTokenResult
::challenge_bypass_ristretto::BlindedTokenResult *cxxbridge1$box$challenge_bypass_ristretto$BlindedTokenResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$BlindedTokenResult$dealloc(::challenge_bypass_ristretto::BlindedTokenResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$BlindedTokenResult$drop(::rust::Box<::challenge_bypass_ristretto::BlindedTokenResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BlindedTokenResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SignedTokenResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SignedTokenResult
::challenge_bypass_ristretto::SignedTokenResult *cxxbridge1$box$challenge_bypass_ristretto$SignedTokenResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$SignedTokenResult$dealloc(::challenge_bypass_ristretto::SignedTokenResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$SignedTokenResult$drop(::rust::Box<::challenge_bypass_ristretto::SignedTokenResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SignedTokenResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$VerificationKey
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$VerificationKey
::challenge_bypass_ristretto::VerificationKey *cxxbridge1$box$challenge_bypass_ristretto$VerificationKey$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$VerificationKey$dealloc(::challenge_bypass_ristretto::VerificationKey *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$VerificationKey$drop(::rust::Box<::challenge_bypass_ristretto::VerificationKey> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$VerificationKey

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$UnblindedTokenResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$UnblindedTokenResult
::challenge_bypass_ristretto::UnblindedTokenResult *cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokenResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokenResult$dealloc(::challenge_bypass_ristretto::UnblindedTokenResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokenResult$drop(::rust::Box<::challenge_bypass_ristretto::UnblindedTokenResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$UnblindedTokenResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SigningKey
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SigningKey
::challenge_bypass_ristretto::SigningKey *cxxbridge1$box$challenge_bypass_ristretto$SigningKey$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$SigningKey$dealloc(::challenge_bypass_ristretto::SigningKey *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$SigningKey$drop(::rust::Box<::challenge_bypass_ristretto::SigningKey> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SigningKey

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$PublicKey
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$PublicKey
::challenge_bypass_ristretto::PublicKey *cxxbridge1$box$challenge_bypass_ristretto$PublicKey$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$PublicKey$dealloc(::challenge_bypass_ristretto::PublicKey *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$PublicKey$drop(::rust::Box<::challenge_bypass_ristretto::PublicKey> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$PublicKey

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$UnblindedToken
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$UnblindedToken
::challenge_bypass_ristretto::UnblindedToken *cxxbridge1$box$challenge_bypass_ristretto$UnblindedToken$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$UnblindedToken$dealloc(::challenge_bypass_ristretto::UnblindedToken *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$UnblindedToken$drop(::rust::Box<::challenge_bypass_ristretto::UnblindedToken> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$UnblindedToken

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SigningKeyResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SigningKeyResult
::challenge_bypass_ristretto::SigningKeyResult *cxxbridge1$box$challenge_bypass_ristretto$SigningKeyResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$SigningKeyResult$dealloc(::challenge_bypass_ristretto::SigningKeyResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$SigningKeyResult$drop(::rust::Box<::challenge_bypass_ristretto::SigningKeyResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SigningKeyResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$PublicKeyResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$PublicKeyResult
::challenge_bypass_ristretto::PublicKeyResult *cxxbridge1$box$challenge_bypass_ristretto$PublicKeyResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$PublicKeyResult$dealloc(::challenge_bypass_ristretto::PublicKeyResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$PublicKeyResult$drop(::rust::Box<::challenge_bypass_ristretto::PublicKeyResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$PublicKeyResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$VerificationSignature
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$VerificationSignature
::challenge_bypass_ristretto::VerificationSignature *cxxbridge1$box$challenge_bypass_ristretto$VerificationSignature$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$VerificationSignature$dealloc(::challenge_bypass_ristretto::VerificationSignature *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$VerificationSignature$drop(::rust::Box<::challenge_bypass_ristretto::VerificationSignature> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$VerificationSignature

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$VerificationSignatureResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$VerificationSignatureResult
::challenge_bypass_ristretto::VerificationSignatureResult *cxxbridge1$box$challenge_bypass_ristretto$VerificationSignatureResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$VerificationSignatureResult$dealloc(::challenge_bypass_ristretto::VerificationSignatureResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$VerificationSignatureResult$drop(::rust::Box<::challenge_bypass_ristretto::VerificationSignatureResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$VerificationSignatureResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BatchDLEQProofResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BatchDLEQProofResult
::challenge_bypass_ristretto::BatchDLEQProofResult *cxxbridge1$box$challenge_bypass_ristretto$BatchDLEQProofResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$BatchDLEQProofResult$dealloc(::challenge_bypass_ristretto::BatchDLEQProofResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$BatchDLEQProofResult$drop(::rust::Box<::challenge_bypass_ristretto::BatchDLEQProofResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BatchDLEQProofResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$UnblindedTokensResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$UnblindedTokensResult
::challenge_bypass_ristretto::UnblindedTokensResult *cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokensResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokensResult$dealloc(::challenge_bypass_ristretto::UnblindedTokensResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokensResult$drop(::rust::Box<::challenge_bypass_ristretto::UnblindedTokensResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$UnblindedTokensResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$TokensResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$TokensResult
::challenge_bypass_ristretto::TokensResult *cxxbridge1$box$challenge_bypass_ristretto$TokensResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$TokensResult$dealloc(::challenge_bypass_ristretto::TokensResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$TokensResult$drop(::rust::Box<::challenge_bypass_ristretto::TokensResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$TokensResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BlindedTokensResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BlindedTokensResult
::challenge_bypass_ristretto::BlindedTokensResult *cxxbridge1$box$challenge_bypass_ristretto$BlindedTokensResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$BlindedTokensResult$dealloc(::challenge_bypass_ristretto::BlindedTokensResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$BlindedTokensResult$drop(::rust::Box<::challenge_bypass_ristretto::BlindedTokensResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$BlindedTokensResult

#ifndef CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SignedTokensResult
#define CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SignedTokensResult
::challenge_bypass_ristretto::SignedTokensResult *cxxbridge1$box$challenge_bypass_ristretto$SignedTokensResult$alloc() noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$SignedTokensResult$dealloc(::challenge_bypass_ristretto::SignedTokensResult *) noexcept;
void cxxbridge1$box$challenge_bypass_ristretto$SignedTokensResult$drop(::rust::Box<::challenge_bypass_ristretto::SignedTokensResult> *ptr) noexcept;
#endif // CXXBRIDGE1_RUST_BOX_challenge_bypass_ristretto$SignedTokensResult

#ifndef CXXBRIDGE1_RUST_VEC_challenge_bypass_ristretto$UnblindedToken
#define CXXBRIDGE1_RUST_VEC_challenge_bypass_ristretto$UnblindedToken
void cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$new(const ::rust::Vec<::challenge_bypass_ristretto::UnblindedToken> *ptr) noexcept;
void cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$drop(::rust::Vec<::challenge_bypass_ristretto::UnblindedToken> *ptr) noexcept;
::std::size_t cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$len(const ::rust::Vec<::challenge_bypass_ristretto::UnblindedToken> *ptr) noexcept;
::std::size_t cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$capacity(const ::rust::Vec<::challenge_bypass_ristretto::UnblindedToken> *ptr) noexcept;
const ::challenge_bypass_ristretto::UnblindedToken *cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$data(const ::rust::Vec<::challenge_bypass_ristretto::UnblindedToken> *ptr) noexcept;
void cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$reserve_total(::rust::Vec<::challenge_bypass_ristretto::UnblindedToken> *ptr, ::std::size_t cap) noexcept;
void cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$set_len(::rust::Vec<::challenge_bypass_ristretto::UnblindedToken> *ptr, ::std::size_t len) noexcept;
::std::size_t cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$stride() noexcept;
#endif // CXXBRIDGE1_RUST_VEC_challenge_bypass_ristretto$UnblindedToken
} // extern "C"

namespace rust {
inline namespace cxxbridge1 {
template <>
::challenge_bypass_ristretto::TokenPreimageResult *Box<::challenge_bypass_ristretto::TokenPreimageResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$TokenPreimageResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::TokenPreimageResult>::allocation::dealloc(::challenge_bypass_ristretto::TokenPreimageResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$TokenPreimageResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::TokenPreimageResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$TokenPreimageResult$drop(this);
}
template <>
::challenge_bypass_ristretto::Token *Box<::challenge_bypass_ristretto::Token>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$Token$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::Token>::allocation::dealloc(::challenge_bypass_ristretto::Token *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$Token$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::Token>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$Token$drop(this);
}
template <>
::challenge_bypass_ristretto::BlindedToken *Box<::challenge_bypass_ristretto::BlindedToken>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$BlindedToken$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::BlindedToken>::allocation::dealloc(::challenge_bypass_ristretto::BlindedToken *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$BlindedToken$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::BlindedToken>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$BlindedToken$drop(this);
}
template <>
::challenge_bypass_ristretto::TokenResult *Box<::challenge_bypass_ristretto::TokenResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$TokenResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::TokenResult>::allocation::dealloc(::challenge_bypass_ristretto::TokenResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$TokenResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::TokenResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$TokenResult$drop(this);
}
template <>
::challenge_bypass_ristretto::BlindedTokenResult *Box<::challenge_bypass_ristretto::BlindedTokenResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$BlindedTokenResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::BlindedTokenResult>::allocation::dealloc(::challenge_bypass_ristretto::BlindedTokenResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$BlindedTokenResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::BlindedTokenResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$BlindedTokenResult$drop(this);
}
template <>
::challenge_bypass_ristretto::SignedTokenResult *Box<::challenge_bypass_ristretto::SignedTokenResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$SignedTokenResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::SignedTokenResult>::allocation::dealloc(::challenge_bypass_ristretto::SignedTokenResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$SignedTokenResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::SignedTokenResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$SignedTokenResult$drop(this);
}
template <>
::challenge_bypass_ristretto::VerificationKey *Box<::challenge_bypass_ristretto::VerificationKey>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$VerificationKey$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::VerificationKey>::allocation::dealloc(::challenge_bypass_ristretto::VerificationKey *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$VerificationKey$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::VerificationKey>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$VerificationKey$drop(this);
}
template <>
::challenge_bypass_ristretto::UnblindedTokenResult *Box<::challenge_bypass_ristretto::UnblindedTokenResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokenResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::UnblindedTokenResult>::allocation::dealloc(::challenge_bypass_ristretto::UnblindedTokenResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokenResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::UnblindedTokenResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokenResult$drop(this);
}
template <>
::challenge_bypass_ristretto::SigningKey *Box<::challenge_bypass_ristretto::SigningKey>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$SigningKey$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::SigningKey>::allocation::dealloc(::challenge_bypass_ristretto::SigningKey *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$SigningKey$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::SigningKey>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$SigningKey$drop(this);
}
template <>
::challenge_bypass_ristretto::PublicKey *Box<::challenge_bypass_ristretto::PublicKey>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$PublicKey$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::PublicKey>::allocation::dealloc(::challenge_bypass_ristretto::PublicKey *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$PublicKey$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::PublicKey>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$PublicKey$drop(this);
}
template <>
::challenge_bypass_ristretto::UnblindedToken *Box<::challenge_bypass_ristretto::UnblindedToken>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$UnblindedToken$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::UnblindedToken>::allocation::dealloc(::challenge_bypass_ristretto::UnblindedToken *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$UnblindedToken$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::UnblindedToken>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$UnblindedToken$drop(this);
}
template <>
::challenge_bypass_ristretto::SigningKeyResult *Box<::challenge_bypass_ristretto::SigningKeyResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$SigningKeyResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::SigningKeyResult>::allocation::dealloc(::challenge_bypass_ristretto::SigningKeyResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$SigningKeyResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::SigningKeyResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$SigningKeyResult$drop(this);
}
template <>
::challenge_bypass_ristretto::PublicKeyResult *Box<::challenge_bypass_ristretto::PublicKeyResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$PublicKeyResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::PublicKeyResult>::allocation::dealloc(::challenge_bypass_ristretto::PublicKeyResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$PublicKeyResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::PublicKeyResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$PublicKeyResult$drop(this);
}
template <>
::challenge_bypass_ristretto::VerificationSignature *Box<::challenge_bypass_ristretto::VerificationSignature>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$VerificationSignature$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::VerificationSignature>::allocation::dealloc(::challenge_bypass_ristretto::VerificationSignature *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$VerificationSignature$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::VerificationSignature>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$VerificationSignature$drop(this);
}
template <>
::challenge_bypass_ristretto::VerificationSignatureResult *Box<::challenge_bypass_ristretto::VerificationSignatureResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$VerificationSignatureResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::VerificationSignatureResult>::allocation::dealloc(::challenge_bypass_ristretto::VerificationSignatureResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$VerificationSignatureResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::VerificationSignatureResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$VerificationSignatureResult$drop(this);
}
template <>
::challenge_bypass_ristretto::BatchDLEQProofResult *Box<::challenge_bypass_ristretto::BatchDLEQProofResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$BatchDLEQProofResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::BatchDLEQProofResult>::allocation::dealloc(::challenge_bypass_ristretto::BatchDLEQProofResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$BatchDLEQProofResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::BatchDLEQProofResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$BatchDLEQProofResult$drop(this);
}
template <>
::challenge_bypass_ristretto::UnblindedTokensResult *Box<::challenge_bypass_ristretto::UnblindedTokensResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokensResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::UnblindedTokensResult>::allocation::dealloc(::challenge_bypass_ristretto::UnblindedTokensResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokensResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::UnblindedTokensResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$UnblindedTokensResult$drop(this);
}
template <>
::challenge_bypass_ristretto::TokensResult *Box<::challenge_bypass_ristretto::TokensResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$TokensResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::TokensResult>::allocation::dealloc(::challenge_bypass_ristretto::TokensResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$TokensResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::TokensResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$TokensResult$drop(this);
}
template <>
::challenge_bypass_ristretto::BlindedTokensResult *Box<::challenge_bypass_ristretto::BlindedTokensResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$BlindedTokensResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::BlindedTokensResult>::allocation::dealloc(::challenge_bypass_ristretto::BlindedTokensResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$BlindedTokensResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::BlindedTokensResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$BlindedTokensResult$drop(this);
}
template <>
::challenge_bypass_ristretto::SignedTokensResult *Box<::challenge_bypass_ristretto::SignedTokensResult>::allocation::alloc() noexcept {
  return cxxbridge1$box$challenge_bypass_ristretto$SignedTokensResult$alloc();
}
template <>
void Box<::challenge_bypass_ristretto::SignedTokensResult>::allocation::dealloc(::challenge_bypass_ristretto::SignedTokensResult *ptr) noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$SignedTokensResult$dealloc(ptr);
}
template <>
void Box<::challenge_bypass_ristretto::SignedTokensResult>::drop() noexcept {
  cxxbridge1$box$challenge_bypass_ristretto$SignedTokensResult$drop(this);
}
template <>
Vec<::challenge_bypass_ristretto::UnblindedToken>::Vec() noexcept {
  cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$new(this);
}
template <>
void Vec<::challenge_bypass_ristretto::UnblindedToken>::drop() noexcept {
  return cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$drop(this);
}
template <>
::std::size_t Vec<::challenge_bypass_ristretto::UnblindedToken>::size() const noexcept {
  return cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$len(this);
}
template <>
::std::size_t Vec<::challenge_bypass_ristretto::UnblindedToken>::capacity() const noexcept {
  return cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$capacity(this);
}
template <>
const ::challenge_bypass_ristretto::UnblindedToken *Vec<::challenge_bypass_ristretto::UnblindedToken>::data() const noexcept {
  return cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$data(this);
}
template <>
void Vec<::challenge_bypass_ristretto::UnblindedToken>::reserve_total(::std::size_t cap) noexcept {
  return cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$reserve_total(this, cap);
}
template <>
void Vec<::challenge_bypass_ristretto::UnblindedToken>::set_len(::std::size_t len) noexcept {
  return cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$set_len(this, len);
}
template <>
::std::size_t Vec<::challenge_bypass_ristretto::UnblindedToken>::stride() noexcept {
  return cxxbridge1$rust_vec$challenge_bypass_ristretto$UnblindedToken$stride();
}
} // namespace cxxbridge1
} // namespace rust
