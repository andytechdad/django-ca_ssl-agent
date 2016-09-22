package agent

import (
  "os"
  "net"
  "reflect"
  "encoding/pem"
  "crypto/x509"
  "crypto/x509/pkix"
  "io/ioutil"
  "crypto/rsa"
  "crypto/rand"
  "encoding/asn1"

	jww "github.com/spf13/jwalterweatherman"
)

func checkCSR(csrpath string, confcsr []byte) (bool) {

  csrfile, err := ioutil.ReadFile(csrpath)
  if err != nil {
    jww.WARN.Println(err)
    return false
  }

  csrequest, _ := pem.Decode(csrfile)
  if csrequest == nil {
    jww.ERROR.Println(csrpath, "is not a valid PEM formatted CSR")
    return false
  }

  csr, err := x509.ParseCertificateRequest(csrequest.Bytes)
  if err != nil {
    jww.ERROR.Println(err)
    return false
  }

  ccsr, err := x509.ParseCertificateRequest(confcsr)
  if err != nil {
    jww.ERROR.Println(err)
    return false
  }

  mismatch := false
  if !reflect.DeepEqual(csr.Subject, ccsr.Subject) {
    jww.WARN.Println("CSR subject configuration mismatch")
    mismatch = true
  }

  if !reflect.DeepEqual(csr.DNSNames, ccsr.DNSNames) {
    jww.WARN.Println("CSR SAN DNS Names configuration mismatch")
    mismatch = true
  }

  if !reflect.DeepEqual(csr.IPAddresses, ccsr.IPAddresses) {
    jww.WARN.Println("CSR SAN IP Addresses configuration mismatch")
    mismatch = true
  }

  if !reflect.DeepEqual(csr.SignatureAlgorithm, ccsr.SignatureAlgorithm) {
    jww.WARN.Println("CSR signature algorithm configuration mismatch")
    mismatch = true
  }

  if mismatch {
    jww.ERROR.Println("CSR found does not match configuration, regenerating")
    return false
  }

  jww.INFO.Println("Valid csr", csrpath, "found")
  return true
}

func newCSR(csrpath string, csrbytes []byte) {
  jww.WARN.Println("Creating new CSR", csrpath)

  csrfile, err := os.Create(csrpath)
  if err != nil {
    jww.ERROR.Println(err)
    os.Exit(1)
  }

  var pemcsr = &pem.Block{
    Type : "CERTIFICATE REQUEST",
    Bytes : csrbytes,
  }
  pem.Encode(csrfile, pemcsr)
  csrfile.Close()

  jww.INFO.Println("CSR", csrpath, "successfully created")
}

func genCSR(cn string, algorithm string, subject map[string]string, san []string, key *rsa.PrivateKey) ([]byte) {

  oidEmailAddress := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
  emailAddress := subject["emailaddress"]

  var dnsAddresses []string
  dnsAddresses = append(dnsAddresses, cn)

  var ipAddresses []net.IP

  for _, v := range san {
    if ip := net.ParseIP(v); ip != nil {
      ipAddresses = append(ipAddresses, ip)
    } else {
      dnsAddresses = append(dnsAddresses, v)
    }
  }

  subj := pkix.Name{
    CommonName:         cn,
    Country:            []string{subject["c"]},
    Province:           []string{subject["st"]},
    Locality:           []string{subject["l"]},
    Organization:       []string{subject["o"]},
    OrganizationalUnit: []string{subject["ou"]},
  }

  rawSubj := subj.ToRDNSequence()

  rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
    {Type: oidEmailAddress, Value: emailAddress},
  })

  asn1Subj, _ := asn1.Marshal(rawSubj)

  var sigAlgo = x509.SHA256WithRSA

  switch algorithm {
  case "md5":
    sigAlgo = x509.MD5WithRSA
    jww.WARN.Println("Using insecure algorithm", sigAlgo)
  case "sha1":
    sigAlgo = x509.SHA1WithRSA
    jww.WARN.Println("Using insecure algorithm", sigAlgo)
  case "sha256":
    sigAlgo = x509.SHA256WithRSA
  case "sha512":
    sigAlgo = x509.SHA512WithRSA
  default:
    sigAlgo = x509.SHA256WithRSA
  }

  template := x509.CertificateRequest{
    RawSubject:         asn1Subj,
    EmailAddresses:     []string{emailAddress},
    DNSNames:           dnsAddresses,
    IPAddresses:        ipAddresses,
    SignatureAlgorithm: sigAlgo,
  }
  csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, key)

  return csrBytes
}
