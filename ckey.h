#include "common.h"
#include <sstream>

template<typename T>
struct secure_allocator : public std::allocator<T>
{
  typedef std::allocator<T> base;
  typedef typename base::size_type size_type;
  typedef typename base::difference_type  difference_type;
  typedef typename base::pointer pointer;
  typedef typename base::const_pointer const_pointer;
  typedef typename base::reference reference;
  typedef typename base::const_reference const_reference;
  typedef typename base::value_type value_type;
  secure_allocator() throw() {}
  secure_allocator(const secure_allocator& a) throw() : base(a) {}
  ~secure_allocator() throw() {}
  template<typename _Other> struct rebind
  { typedef secure_allocator<_Other> other; };

  void deallocate(T* p, std::size_t n)
  {
    if (p != NULL)
      memset(p, 0, sizeof(T) * n);
    allocator<T>::deallocate(p, n);
  }
};

inline char hex2char(const char* buf) {
    int c = 0;
    sscanf(buf, "%02x", &c);
    return c;
}

inline void hex2string(const std::string& hexstr, std::string& str) {
  const char* p = hexstr.data();
  debug("hex str:%s\n", p);
  while(*p) {
    char c = hex2char(p);
    str += c;
    p += 2;
  }
}

inline std::string str2hex(const std::string& str) {
  char buff[4096] = {0};   
  int index = 0;
  const char* p = str.data();
  for(unsigned int i = 0; i < str.length(); i++) {
    sprintf(buff + index, "%02x", (char)p[i]);
    index += 2;
  }
  return buff;
}

inline std::string str2hex(const vector<unsigned char>& vch) {
  char buff[4096] = {0};   
  int index = 0;
  for(unsigned int i = 0; i < vch.size(); i++) {
    sprintf(buff + index, "%02x", (char)vch[i]);
    index += 2;
  }
  return buff;
}

inline std::string str2hex(const std::vector<unsigned char, secure_allocator<unsigned char> >& vch) {
  char buff[4096] = {0};   
  int index = 0;
  for(unsigned int i = 0; i < vch.size(); i++) {
    sprintf(buff + index, "%02x", (char)vch[i]);
    index += 2;
  }
  return buff;
}

typedef vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;

class CKey {
  protected:
    EC_KEY* pkey;
  public:
    CKey();
    ~CKey();
    void MakeNewKey();

    vector<unsigned char> GetPubKey() const ;
    std::string GetHexPubkey() const;

    CPrivKey GetPrivKey() const ;
    std::string GetHexPrivKey() const;

    bool Sign(const std::string& data, vector<unsigned char>& vchSig);
    bool Verify(const std::string& data, const vector<unsigned char>& vchSig);

    bool SetPrivKey(const CPrivKey& vchPrivKey);
    bool SetPrivKey(const std::string& hexkey); 

    static bool MakekeySign(const std::string& hexkey,
        const std::string& hash, vector<unsigned char>& vchSig);
    static bool MakekeySign(const CPrivKey& vchPrivKey,
        const std::string& hash, vector<unsigned char>& vchSig); 

    bool SetPubKey(const vector<unsigned char>& vchPubKey);
    bool SetPubKey(const std::string& hexkey);

    static bool MakekeyVerify(const std::string& hexpubkey,
        const std::string& hash, const vector<unsigned char>& vchSig);
    static bool MakekeyVerify(const vector<unsigned char>& vchPubKey, 
        const std::string& hash, const vector<unsigned char>& vchSig);

};


template<typename T>
bool check_key(const T& key1, const T& key2) {
  if (key1.size() != key2.size()) {
    debug("data len not same d1:%lu, d2:%lu", key1.size(), key2.size());
    return false;
  }
  const unsigned char* i = &key1[0];
  const unsigned char* j = &key2[0];

  bool bret(false);
  do {
    unsigned int index = 0;
    for (; index < key1.size(); index++) {
      if (*i++ != *j++) {
        break;
      }
    }
    if (index < key1.size()) {
      debug("data1:%s data2:%s\n", str2hex(key1).c_str(), str2hex(key2).c_str());
      break;
    }
    bret = true;
  } while (0);
  return bret;
}


