package agent

import (
  //"time"
  "os"
  //"encoding/gob"
  "encoding/pem"
  //"math/big"
  "crypto/x509"
  //"crypto/x509/pkix"
  "fmt"
  "io/ioutil"
  "crypto/rsa"
  "crypto/rand"

	jww "github.com/spf13/jwalterweatherman"
	"github.com/spf13/viper"
)

func initConfig() {
  viper.SetConfigType("yaml")
  viper.SetConfigName("agent")
  viper.AddConfigPath("/etc/ca-agent/")
  viper.AddConfigPath("$HOME/.ca-agent/")
  viper.AddConfigPath("./config/")
  viper.AddConfigPath(".")

  err := viper.ReadInConfig()
  if err != nil {
      panic(fmt.Errorf("Fatal error config file: %s \n", err))
  }

  viper.SetDefault("logging.level", "INFO")
  viper.SetDefault("logging.path", "logs")
}

func initLog(logfile string, loglevel string) {
  jww.SetLogFile(logfile)
  switch loglevel {
  case "INFO":
    jww.SetLogThreshold(jww.LevelInfo)
  case "WARN":
    jww.SetLogThreshold(jww.LevelWarn)
  case "ERROR":
    jww.SetLogThreshold(jww.LevelError)
  default:
    jww.SetLogThreshold(jww.LevelWarn)
  }
}

func checkKey(keypath string) (bool) {

  keyfile, err := ioutil.ReadFile(keypath)
  if err != nil {
    jww.WARN.Println(err)
    return false
  }

  key, _ := pem.Decode(keyfile)
  if key == nil {
    jww.ERROR.Println(keypath, "is not a valid PEM formatted key")
    return false
  }

  if _, err := x509.ParsePKCS1PrivateKey(key.Bytes); err != nil {
    jww.ERROR.Println(err)
    return false
  }

  jww.INFO.Println("Valid key", keypath, "found")
  return true
}

func newKey(keypath string) {

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
}

func checkCSR(csrpath string) (bool) {

  csrfile, err := ioutil.ReadFile(csrpath)
  if err != nil {
    jww.WARN.Println(err)
    return false
  }

  csr, _ := pem.Decode(csrfile)
  if csr == nil {
    jww.ERROR.Println(csrpath, "is not a valid PEM formatted CSR")
    return false
  }

  return false
}

func newCSR(csrpath string) {

}

func checkCrt(crtpath string) (bool) {
  return false
}

func newCrt(crtpath string) {

}

func Execute() {
  initConfig()

  logpath := viper.GetString("logging.path")
  logfile := logpath + "/agent.log"
  loglevel := viper.GetString("logging.level")
  initLog(logfile, loglevel)

  certpath := viper.GetString("certs.path")
  commonname := viper.GetString("csr.cn")
  privkey := certpath + "/" + commonname + ".key"
  pubkey := certpath + "/" + commonname + ".crt"
  csr := certpath + "/" + commonname + ".csr"

  if checkKey(privkey) == false {
    //key is either corrupt or doesn't exist
    newKey(privkey)
  }

  if checkCSR(csr) == false {
    //CSR is either not there or doesn't match the configuration
    newCSR(csr)
  }

  if checkCrt(pubkey) {
    //crt is either invalid, expired or not there
    newCrt(pubkey)
  }
}
