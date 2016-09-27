package agent

import (
  "os"
  "encoding/pem"
  "crypto/x509"
  "io/ioutil"
  "crypto/rsa"
  "crypto/rand"

	jww "github.com/spf13/jwalterweatherman"
)

func checkKey(keypath string, keybits int) (bool, *rsa.PrivateKey) {

  if keybits % 8 != 0 {
    jww.ERROR.Println(keybits, "is not a valid key length, 2048 is a good value")
    os.Exit(1)
  }

  keyfile, err := ioutil.ReadFile(keypath)
  if err != nil {
    jww.WARN.Println(err)
    return false, nil
  }

  key, _ := pem.Decode(keyfile)
  if key == nil {
    jww.ERROR.Println(keypath, "is not a valid PEM formatted key")
    return false, nil
  }

  var keyb *rsa.PrivateKey
  if keyb, err = x509.ParsePKCS1PrivateKey(key.Bytes); err != nil {
    jww.ERROR.Println(err)
    return false, nil
  }

  bitlen := len(keyb.PublicKey.N.Bytes()) * 8
  if bitlen != keybits {
    jww.ERROR.Println(keypath, "is", bitlen, "and not", keybits, "bits")
    return false, nil
  }

  jww.INFO.Println("Valid key", keypath, "found")
  return true, keyb
}

func newKey(keypath string, keybits int) (*rsa.PrivateKey){

  jww.WARN.Println("Creating new key", keypath)

  privkey, err := rsa.GenerateKey(rand.Reader, keybits)
  if err != nil {
    jww.ERROR.Println(err)
    os.Exit(1)
  }

  privkeyfile, err := os.Create(keypath)
  if err != nil {
    jww.ERROR.Println(err)
    os.Exit(1)
  }
  privkeyfile.Chmod(0640)

  var pemkey = &pem.Block{
    Type : "RSA PRIVATE KEY",
    Bytes : x509.MarshalPKCS1PrivateKey(privkey),
  }
  pem.Encode(privkeyfile, pemkey)
  privkeyfile.Close()

  jww.INFO.Println("Private key", keypath, "successfully created")
  return privkey
}
