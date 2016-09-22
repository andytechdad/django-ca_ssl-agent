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

func checkKey(keypath string) (bool, *rsa.PrivateKey) {

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

  jww.INFO.Println("Valid key", keypath, "found")
  return true, keyb
}

func newKey(keypath string) (*rsa.PrivateKey){

  jww.WARN.Println("Creating new key", keypath)

  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    jww.ERROR.Println(err)
    os.Exit(1)
  }

  privkeyfile, err := os.Create(keypath)
  if err != nil {
    jww.ERROR.Println(err)
    os.Exit(1)
  }

  var pemkey = &pem.Block{
    Type : "RSA PRIVATE KEY",
    Bytes : x509.MarshalPKCS1PrivateKey(privkey),
  }
  pem.Encode(privkeyfile, pemkey)
  privkeyfile.Close()

  jww.INFO.Println("Private key", keypath, "successfully created")
  return privkey
}
