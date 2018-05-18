#include "ckey.h"

bool test_key(CKey& key) {
  vector<unsigned char> vchSig;
  std::string data("leef");
  if(!key.Sign(data, vchSig)) {
    debug("Sign failed\n");
    return false;
  }
  if (!key.Verify(data, vchSig)) {
    debug("Verify failed\n");
    return false;
  }
  return true;
}

void CheckSleep() {
  static time_t t;
  if (time(0) - t > 60) {
    debug("alive");
    t = time(0);
  }
  usleep(5);
}

void FindPriKeyFromPubKey(std::vector<std::string>& pub_key_arry) {
  for (const auto& it : pub_key_arry) {
    while (1) {
      CheckSleep();
      CKey key;
      key.MakeNewKey(); 
      if (it == key.GetHexPubkey()) {
        debug("find pubkey:%s\nprikey:%s", key.GetHexPubkey().c_str(), key.GetHexPrivKey().c_str());
        break;
      }
    }
  }
}

int main(int argc, char* argv[]) {
  std::vector<std::string> key_arry;
  key_arry.push_back("0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee");
  key_arry.push_back("047211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073dee6c89064984f03385237d92167c13e236446b417ab79a0fcae412ae3316b77");
  key_arry.push_back("0494b9d3e76c5b1629ecf97fff95d7a4bbdac87cc26099ada28066c6ff1eb9191223cd897194a08d0c2726c5747f1db49e8cf90e75dc3e3550ae9b30086f3cd5aa");
  FindPriKeyFromPubKey(key_arry);
  // CKey key;
  // key.MakeNewKey();
  // if (!test_key(key)) {
  //   debug("test_key failed\n");
  //   return false;
  // }
  // auto hex_pubkey = key.GetHexPubkey();
  // auto hex_prikey = key.GetHexPrivKey();
  // debug("pubkey:%s\nprikey:%s\n", hex_pubkey.c_str(), hex_prikey.c_str());
  // {
  //   CKey test_key;
  //   if (!test_key.SetPrivKey(hex_prikey)){
  //     debug("SetPrivKey failed");
  //     return -1;
  //   }
  //   if (hex_prikey != test_key.GetHexPrivKey()) {
  //     debug("..... key error\n");
  //     return -1;
  //   }
  // }
  // vector<unsigned char> vchSig;
  // if (!CKey::MakekeySign(key.GetPrivKey(), "leef", vchSig)) {
  //   debug("err origin MakekeySign failed\n");
  //   return false;
  // }
  // if (!CKey::MakekeyVerify(key.GetPubKey(), "leef", vchSig)) {
  //   debug("err origin MakekeyVerify failed\n");
  //   return false;
  // }
  // debug("origin Sig && Verify sucess\n");

  // vector<unsigned char> vchSig2;
  // if (!CKey::MakekeySign(key.GetHexPrivKey(), "leef", vchSig2)) {
  //   debug("err hex MakekeySign failed\n");
  //   return false;
  // }
  // if (!CKey::MakekeyVerify(key.GetHexPubkey(), "leef", vchSig2)) {
  //   debug("err hex MakekeyVerify failed\n");
  //   return false;
  // }
  // debug("hex Sig && Verify sucess\n");

  // if (!CKey::MakekeyVerify(key.GetHexPubkey(), "leef", vchSig)) {
  //   debug("err hex Verify origin MakekeyVerify failed\n");
  //   return false;
  // }
  return 0;
}
