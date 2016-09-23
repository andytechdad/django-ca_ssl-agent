package agent

import (
  "fmt"
  "crypto/rsa"
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
  viper.SetDefault("csr.profile", "webserver")
  viper.SetDefault("csr.algorithm", "sha256")
  viper.SetDefault("certs.keybits", 2048)
  viper.SetDefault("certs.regen", 7)
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
  algo := viper.GetString("csr.algorithm")
  san := viper.GetStringSlice("csr.san")
  subj := viper.GetStringMapString("csr.subject")
  keybits := viper.GetInt("certs.keybits")
  regendays := viper.GetInt("certs.regen")
  ca := viper.GetString("certs.ca")
  url := viper.GetString("api.url")
  authtoken := viper.GetString("api.token")

  var keybytes *rsa.PrivateKey
  var res bool
  if res, keybytes = checkKey(privkey, keybits); res == false {
    //key is either corrupt or doesn't exist
    keybytes = newKey(privkey, keybits)
  }

  configcsr := genCSR(commonname, algo, subj, san, keybytes)
  if checkCSR(csr, configcsr) == false {
    //CSR is either not there or doesn't match the configuration
    newCSR(csr, configcsr)
  }

  if checkCrt(pubkey, regendays, configcsr) == false {
    //crt is either invalid, expired or not there
    crtbytes := getCrt(url, authtoken, ca, algo, configcsr, subj, san)
    newCrt(pubkey, crtbytes)
  }
}
