package agent

import (
  "os"
  "time"
  "sort"
  "strings"
  "reflect"
  "encoding/pem"
  "encoding/json"
  "crypto/x509"
  "io/ioutil"
  "net/http"

	jww "github.com/spf13/jwalterweatherman"
)

func checkCrt(crtpath string, regendays int, confcsr []byte) (bool) {

  crtfile, err := ioutil.ReadFile(crtpath)
  if err != nil {
    jww.WARN.Println(err)
    return false
  }

  crt, _ := pem.Decode(crtfile)
  if crt == nil {
    jww.ERROR.Println(crtpath, "is not a valid PEM formatted certificate")
    return false
  }

  crtb, err := x509.ParseCertificate(crt.Bytes)
  if err != nil {
    jww.ERROR.Println(err)
    return false
  }

  now := time.Now()
  regendate := crtb.NotAfter.AddDate(0, 0, -regendays)
  jww.INFO.Println(crtpath, "expires", crtb.NotAfter)
  jww.INFO.Println(crtpath, "renewal date", regendate)
  if regendate.Before(now) {
    jww.ERROR.Println(crtpath, "renewal due, expiry date", crtb.NotAfter)
    return false
  }

  ccsr, err := x509.ParseCertificateRequest(confcsr)
  if err != nil {
    jww.ERROR.Println(err)
    return false
  }

  mismatch := false
  if !reflect.DeepEqual(crtb.PublicKey, ccsr.PublicKey) {
    jww.WARN.Println("Certificate and CSR public keys do not match")
    mismatch = true
  }

  sort.Strings(ccsr.DNSNames)
  sort.Strings(crtb.DNSNames)
  if !reflect.DeepEqual(crtb.DNSNames, ccsr.DNSNames) {
    jww.WARN.Println("Certificate and CSR DNS names do not match")
    mismatch = true
  }

  var ccsr_ipaddrs []string
  for _, v := range ccsr.IPAddresses {
    ccsr_ipaddrs = append(ccsr_ipaddrs, v.String())
  }

  var crtb_ipaddrs []string
  for _, v := range crtb.IPAddresses {
    crtb_ipaddrs = append(crtb_ipaddrs, v.String())
  }

  sort.Strings(ccsr_ipaddrs)
  sort.Strings(crtb_ipaddrs)
  if !reflect.DeepEqual(ccsr_ipaddrs, crtb_ipaddrs) {
    jww.WARN.Println("Certificate and CSR IP addresses do not match")
    mismatch = true
  }

  if !reflect.DeepEqual(ccsr.SignatureAlgorithm, crtb.SignatureAlgorithm) {
    jww.WARN.Println("Certificate and CSR signing algorithms do not match")
    mismatch = true
  }

  if mismatch {
    jww.ERROR.Println("Certificate found does not match configuration, regenerating")
    return false
  }

  jww.INFO.Println("Valid certificate", crtpath, "found")
  return true
}

type CSRData struct {
  CA        string `json:"ca"`
  CN        string `json:"cn"`
  Subject   map[string]string `json:"subject"`
  SAN       []string `json:"subjectAltName"`
  CSR       string `json:"csr"`
  Algorithm string `json:"algorithm"`
}

func NewCSRData() *CSRData {
  var d CSRData
  d.Subject = make(map[string]string)
  return &d
}

func getCrt(url string, auth string, ca string, algo string, confcsr []byte, subject map[string]string, san []string) (interface{}, interface{}) {
  ccsr, _ := x509.ParseCertificateRequest(confcsr)
  var pemcsr = &pem.Block{
    Type : "CERTIFICATE REQUEST",
    Bytes : confcsr,
  }
  pembytes := pem.EncodeToMemory(pemcsr)
  pemstring := string(pembytes[:])

  data := NewCSRData()
  data.CA = ca
  data.CN = ccsr.Subject.CommonName
  data.Subject = subject
  data.Subject["CN"] = ccsr.Subject.CommonName
  data.SAN = san
  data.CSR = pemstring
  data.Algorithm = algo

  jsondata, _ := json.Marshal(data)
  postdata := strings.NewReader(string(jsondata[:]))

  req, _ := http.NewRequest("POST", url, postdata)
	req.Header.Add("content-type", "application/json")
	req.Header.Add("authorization", "Token " + auth)
	req.Header.Add("cache-control", "no-cache")

	res, err := http.DefaultClient.Do(req)
  if err != nil {
    jww.ERROR.Println(err)
    os.Exit(1)
  }

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

  var jsonbody map[string]interface{}
  jsonbody = make(map[string]interface{})

  json.Unmarshal(body, &jsonbody)

  if res.StatusCode != 201 {
    jww.ERROR.Println("API error,",res.StatusCode,jsonbody["detail"])
    os.Exit(1)
  }

  return jsonbody["pub"], jsonbody["chain"]
}

func newCrt(crtpath string, chainpath string, bundlepath string, crtbytes interface{}, chainbytes interface{}) {
  jww.WARN.Println("Creating new certificate", crtpath)

  if str, ok := crtbytes.(string); ok {

    pemcrt, _ := pem.Decode([]byte(str))
    if pemcrt == nil {
      jww.ERROR.Println("Certificate returned by API is not a valid PEM formatted certificate")
      os.Exit(1)
    }

    if _, err := x509.ParseCertificate(pemcrt.Bytes); err != nil {
      jww.ERROR.Println(err)
      os.Exit(1)
    }

    crtfile, err := os.Create(crtpath)
    if err != nil {
      jww.ERROR.Println(err)
      os.Exit(1)
    }
    pem.Encode(crtfile, pemcrt)
    crtfile.Close()
    jww.INFO.Println("Certificate", crtpath, "successfully created")

  } else {
    jww.ERROR.Println("Certificate returned by API is not a valid PEM formatted certificate")
    os.Exit(1)
  }

  if str, ok := chainbytes.(string); ok {

    pemchain, _ := pem.Decode([]byte(str))
    if pemchain == nil {
      jww.ERROR.Println("Certificate returned by API is not a valid PEM formatted certificate")
      os.Exit(1)
    }

    if _, err := x509.ParseCertificate(pemchain.Bytes); err != nil {
      jww.ERROR.Println(err)
      os.Exit(1)
    }

    chainfile, err := os.Create(chainpath)
    if err != nil {
      jww.ERROR.Println(err)
      os.Exit(1)
    }
    pem.Encode(chainfile, pemchain)
    chainfile.Close()
    jww.INFO.Println("Chain certificate", chainpath, "successfully created")

    certfilecontent, err := ioutil.ReadFile(crtpath)
    if err != nil {
      jww.ERROR.Println(err)
      os.Exit(1)
    }

    bundle, err := os.Create(bundlepath)
    if err != nil {
      jww.ERROR.Println(err)
      os.Exit(1)
    }
    bundle.Close()

    bundlefile, err := os.OpenFile(bundlepath, os.O_APPEND|os.O_WRONLY,0644)
    if err != nil {
      jww.ERROR.Println(err)
      os.Exit(1)
    }
    defer bundlefile.Close()

    if _, err = bundlefile.Write(certfilecontent); err != nil {
      jww.ERROR.Println(err)
      os.Exit(1)
    }
    pem.Encode(bundlefile, pemchain)
    jww.INFO.Println("Bundle certificate", bundlepath, "successfully created")

  } else {
    jww.ERROR.Println("Chain certificate returned by API is not a valid PEM formatted certificate")
    os.Exit(1)
  }



}
