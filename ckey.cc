#include "ckey.h"

CKey::CKey() {
  pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (pkey == NULL)
    debug("CKey::CKey() : EC_KEY_new_by_curve_name failed\n");
}
CKey::~CKey() {
  EC_KEY_free(pkey);
}

void CKey::MakeNewKey() {
  if (!EC_KEY_generate_key(pkey))
    debug("CKey::MakeNewKey() : EC_KEY_generate_key failed\n");
}

vector<unsigned char> CKey::GetPubKey() const {
  int nSize = i2o_ECPublicKey(pkey, NULL);
  vector<unsigned char> vchPubKey(nSize, 0);
  if (!nSize) {
    debug("CKey::GetPubKey() : i2o_ECPublicKey failed\n");
    return vchPubKey;
  }
  unsigned char* pbegin = &vchPubKey[0];
  if (i2o_ECPublicKey(pkey, &pbegin) != nSize)
    debug("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size\n");
  return vchPubKey;
}

std::string CKey::GetHexPubkey() const {
  auto tkey = GetPubKey();
  char str[3] = {0};
  std::stringstream ss;
  for (unsigned int i = 0; i < tkey.size(); i++) {
    sprintf(str, "%02x", tkey[i]);
    ss << str;
  }
  return ss.str();
}

CPrivKey CKey::GetPrivKey() const {
  int nSize = i2d_ECPrivateKey(pkey, NULL);
  if (!nSize) {
    debug("CKey::GetPrivKey() : i2d_ECPrivateKey failed\n");
    return CPrivKey(0,0);
  }
  CPrivKey vchPrivKey(nSize, 0);
  unsigned char* pbegin = &vchPrivKey[0];
  if (i2d_ECPrivateKey(pkey, &pbegin) != nSize) {
    debug("CKey::GetPrivKey() : i2d_ECPrivateKey returned unexpected size");
  }
  return vchPrivKey;
}

std::string CKey::GetHexPrivKey() const {
  auto tkey = GetPrivKey();
  char str[3] = {0};
  std::stringstream ss;
  for (unsigned int i = 0; i < tkey.size(); i++) {
    sprintf(str, "%02x", tkey[i]);
    ss << str;
  }
  return ss.str();

}

bool CKey::Sign(const std::string& data, vector<unsigned char>& vchSig) {
  int data_len = data.length();
  unsigned char* hash = new unsigned char[data.length()];
  memcpy(hash, data.data(), data.length());
  vchSig.clear();
  unsigned char pchSig[10000];
  unsigned int nSize = 0;
  bool bret(false);
  do {
    if (!ECDSA_sign(0, hash, data_len, pchSig, &nSize, pkey)) {
      debug("Sign failed\n");
      break;
    }
    vchSig.resize(nSize);
    memcpy(&vchSig[0], pchSig, nSize);
    bret = true;
  } while (0);
  delete[] hash;
  return bret;
}

bool CKey::Verify(const std::string& data, const vector<unsigned char>& vchSig) {
  int data_len = data.length();
  unsigned char* hash = new unsigned char[data.length()];
  memcpy(hash, data.data(), data.length());
  bool bret(false);
  do {
    if (ECDSA_verify(0, hash, data_len, &vchSig[0], vchSig.size(), pkey) != 1) {
      debug("Verify failed\n");
      break;
    }
    bret = true;
  } while (0);
  delete[] hash;
  return bret;
}


bool CKey::SetPrivKey(const CPrivKey& vchPrivKey) {
  const unsigned char* pbegin = &vchPrivKey[0];
  if (!d2i_ECPrivateKey(&pkey, &pbegin, vchPrivKey.size())) {
    return false;
  }
  return true;
}

bool CKey::SetPrivKey(const std::string& hexkey) {
  std::string prikey;
  hex2string(hexkey, prikey);
  CPrivKey vchPrivKey(prikey.length(), 0);
  unsigned char* pbegin = &vchPrivKey[0];
  for (unsigned int i = 0; i < prikey.length(); i++) {
    *pbegin++ = prikey.data()[i];
  }
  return SetPrivKey(vchPrivKey);
}

bool CKey::MakekeySign(const std::string& hexkey,
    const std::string& hash, vector<unsigned char>& vchSig) {
  CKey key;
  if (!key.SetPrivKey(hexkey)) {
    debug("MakekeySign SetPrivKey failed\n");
    return false;
  }
  return key.Sign(hash, vchSig);
}

bool CKey::MakekeySign(const CPrivKey& vchPrivKey,
    const std::string& hash, vector<unsigned char>& vchSig) {
  CKey key;
  if (!key.SetPrivKey(vchPrivKey)) {
    debug("MakekeySign SetPrivKey failed\n");
    return false;
  }
  return key.Sign(hash, vchSig);
}


bool CKey::SetPubKey(const vector<unsigned char>& vchPubKey) {
  const unsigned char* pbegin = &vchPubKey[0];
  if (!o2i_ECPublicKey(&pkey, &pbegin, vchPubKey.size()))
    return false;
  return true;
}

bool CKey::SetPubKey(const std::string& hexkey) {
  std::string pubkey;
  hex2string(hexkey, pubkey);

  vector<unsigned char> vchPubKey(pubkey.length(), 0);
  unsigned char* pbegin = &vchPubKey[0];
  for (unsigned int i = 0; i < pubkey.length(); i++) {
    *pbegin++ = pubkey.data()[i];
  }
  return SetPubKey(vchPubKey);

}

bool CKey::MakekeyVerify(const std::string& hexpubkey,
    const std::string& hash, const vector<unsigned char>& vchSig) {
  CKey key;
  if (!key.SetPubKey(hexpubkey))
    return false;
  return key.Verify(hash, vchSig);
}

bool CKey::MakekeyVerify(const vector<unsigned char>& vchPubKey,
    const std::string& hash, const vector<unsigned char>& vchSig) {
  CKey key;
  if (!key.SetPubKey(vchPubKey))
    return false;
  return key.Verify(hash, vchSig);
}

