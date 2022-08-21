package resolver

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/miekg/dns"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
	"github.com/semihalev/log"
	"hash/fnv"
	"os"
	"strings"
	"time"
)

const (
	// TODO for rootzone
	DNSrhineCertPrefix = "_rhinecert."
	DNSdsumprefix      = "_dsum."
	txtrhinecertprefix = "rhineCert Ed25519"

	_RO               = 1 << 14 // RHINE OK
	defaultUDPBufSize = 2048
)

type ROA struct {
	rcert  *dns.TXT
	dSum   *dns.TXT
	dnskey *dns.DNSKEY
	keySig *dns.RRSIG
}

func verifyRhineROA(roa *ROA, certFile string, pubFile string) bool {
	rcert, publiKey, err := ParseVerifyRhineCertTxtEntry(roa.rcert, certFile)
	if err != nil {
		log.Warn(err.Error())
		return false
	}
	log.Debug("RCert successfully parsed")

	_, err = ParseVerifyDSum(roa.dSum, rcert, pubFile)
	if err != nil {
		log.Warn(err.Error())
		return false
	}

	sig := roa.keySig
	key := roa.dnskey
	var expired string
	if !sig.ValidityPeriod(time.Now().UTC()) {
		expired = "(*EXPIRED*)"
	}
	if err := sig.VerifyWithPublicKey(publiKey, []dns.RR{key}); err != nil {
		log.Warn("[RHINE] ;- Bogus signature, %s does not validate (RCert) [%s] %s\n",
			shortSig(sig), err.Error(), expired)
		return false
	}

	return true
}

func ParseVerifyDSum(txt *dns.TXT, rcert *x509.Certificate, pubFile string) (dSum *rhine.DSum, err error) {
	entries := txt.Txt
	entry := strings.Join(entries, "")

	dSum = &rhine.DSum{}
	if err = dSum.DeserializeFromString(entry); err != nil {
		return nil, err
	}

	pub, err := rhine.PublicKeyFromFile(pubFile)
	if err != nil {
		return nil, err
	}

	if !dSum.Verify(pub, rcert) {
		return nil, errors.New("failed to validate DSum")
	}

	return dSum, nil
}
func ParseVerifyRhineCertTxtEntry(txt *dns.TXT, certFile string) (*x509.Certificate, ed25519.PublicKey, error) {
	//TODO support other key types
	entries := txt.Txt
	entry := strings.Join(entries, " ")
	certstringchunks := strings.SplitAfter(entry, txtrhinecertprefix)[1:]
	encodedcert := strings.Join(certstringchunks, "")
	encodedcert = strings.ReplaceAll(encodedcert, " ", "")

	certdecoded, _ := base64.StdEncoding.DecodeString(encodedcert)

	cert, err := x509.ParseCertificate(certdecoded)
	if err != nil {
		log.Warn("Parsing Rhine Cert failed! ", err)
		return nil, nil, err
	}

	// TODO(lou): Enable Cert verification later
	name := txt.Header().Name
	apexname := strings.SplitAfter(name, DNSrhineCertPrefix)[1]
	var CaCertPool *x509.CertPool
	CaCertPool, _ = x509.SystemCertPool()

	CaCert, err := os.ReadFile(certFile)
	CaCertPool.AppendCertsFromPEM(CaCert)

	if _, err := cert.Verify(x509.VerifyOptions{
		DNSName: apexname,
		Roots:   CaCertPool,
	}); err != nil {
		log.Warn("Rhine Cert Verification Failed!", err)
		return nil, nil, err
	}

	return cert, cert.PublicKey.(ed25519.PublicKey), nil
}

func extractROAFromMsg(msg *dns.Msg) (roa *ROA, ok bool) {
	var (
		rcert  *dns.TXT
		dnskey *dns.DNSKEY
		keySig *dns.RRSIG
		dsum   *dns.TXT
	)
	rrs := msg.Answer
	rrs = append(rrs, msg.Extra...)
	for _, r := range rrs {
		switch r.Header().Rrtype {
		case dns.TypeDNSKEY:
			dnskey = r.(*dns.DNSKEY)
		case dns.TypeTXT:
			txt := r.(*dns.TXT)
			if IsRCert(txt) {
				rcert = txt
			} else if IsDSum(txt) {
				dsum = txt
			}
		case dns.TypeRRSIG:
			rrsig := r.(*dns.RRSIG)
			if rrsig.TypeCovered == dns.TypeDNSKEY {
				keySig = rrsig
			}
		}
	}

	if rcert == nil || dnskey == nil || keySig == nil {
		return nil, false
	}

	return &ROA{keySig: keySig, rcert: rcert, dnskey: dnskey, dSum: dsum}, true
}

func addROAToMsg(roa *ROA, msg *dns.Msg) {
	msg.Extra = append(msg.Extra, roa.dnskey)
	msg.Extra = append(msg.Extra, roa.rcert)
	msg.Extra = append(msg.Extra, roa.keySig)
	if roa.dSum != nil {
		msg.Extra = append(msg.Extra, roa.dSum)
	}
}
func IsRCert(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSrhineCertPrefix)
}

func IsDSum(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSdsumprefix)
}

func rhineRRSigCheck(in *dns.Msg, key *dns.DNSKEY) bool {
	if key == nil {
		log.Warn("[RHINE] DNSKEY not found for RRSIG checking\n")
		return false
	}
	log.Debug("[RHINE] Start checking RRSIG in Answer section\n")
	if !sectionCheck(in.Answer, key) {
		return false
	}
	log.Debug("[RHINE] Start checking RRSIG in Ns section\n")
	if !sectionCheck(in.Ns, key) {
		return false
	}
	return true
}

func sectionCheck(set []dns.RR, key *dns.DNSKEY) (ok bool) {
	ok = true
	for _, rr := range set {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			var expired string
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				expired = "(*EXPIRED*)"
			}
			rrset := getRRset(set, rr.Header().Name, rr.(*dns.RRSIG).TypeCovered)
			if err := rr.(*dns.RRSIG).Verify(key, rrset); err != nil {
				log.Warn("[RHINE] ;- Bogus signature, %s does not validate (DNSKEY %s/%d) [%s] %s\n",
					shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), err.Error(), expired)
				ok = false
			} else {
				log.Info("[RHINE] ;+ Secure signature, %s validates (DNSKEY %s/%d) %s\n", shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), expired)
			}
		}
	}

	return ok
}

func shortSig(sig *dns.RRSIG) string {
	return sig.Header().Name + " RRSIG(" + dns.TypeToString[sig.TypeCovered] + ")"
}

func getRRset(l []dns.RR, name string, t uint16) []dns.RR {
	var l1 []dns.RR
	for _, rr := range l {
		if strings.ToLower(rr.Header().Name) == strings.ToLower(name) && rr.Header().Rrtype == t {
			l1 = append(l1, rr)
		}
	}
	return l1
}

func hash(qname string) uint64 {
	h := fnv.New64()
	h.Write([]byte(qname))
	return h.Sum64()
}
