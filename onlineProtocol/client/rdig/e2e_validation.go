package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/miekg/dns"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
	"os"
	"strings"
	"time"
)

const (
	DNSrhineCertPrefix = "_rhinecert."
	DNSdsumprefix      = "_dsum."

	txtrhinecertprefix = "rhineCert Ed25519"
	txtsigvalueprefix  = "rhineSig "
	defaultUDPBufSize  = 2048
)

type ROA struct {
	rcert  *dns.TXT
	dsum   *dns.TXT
	dnskey *dns.DNSKEY
	keySig *dns.RRSIG
}

func Size(m *dns.Msg) {
	o := m.IsEdns0()
	if o != nil {
		o.SetUDPSize(defaultUDPBufSize)
		return
	}

	o = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetUDPSize(defaultUDPBufSize)
	m.Extra = append(m.Extra, o)
}

func verifyRhineROA(roa *ROA, certFile string, pubKeyFile string) bool {
	rcert, publiKey, err := ParseVerifyRhineCertTxtEntry(roa.rcert, certFile)
	if err != nil {
		fmt.Printf("[RHINE] RCert parse faild, error: %s\n", err.Error())
		return false
	}
	fmt.Printf("[RHINE] RCert successfully parsed\n")

	_, err = ParseVerifyDSum(roa.dsum, rcert, pubKeyFile)
	if err != nil {
		fmt.Printf("[RHINE] Failed to parse and verify DSum, err: %s", err.Error())
		return false
	}

	if err := roa.keySig.VerifyWithPublicKey(publiKey, []dns.RR{roa.dnskey}); err != nil {
		fmt.Printf("[RHINE] RhineSig verification failed, %s \n", err)
		return false
	} else {
		fmt.Printf("[RHINE] RhineSig successfully verified\n")
		return true
	}
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
		fmt.Printf("[RHINE] Failed to validate DSum\n")
	} else {
		fmt.Printf("[RHINE] DSum verified\n")
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

	CaCert, err := os.ReadFile(certFile)
	cert, err := x509.ParseCertificate(certdecoded)
	if err != nil {
		fmt.Println("Parsing Rhine Cert failed! ", err)
		return nil, nil, err
	}

	name := txt.Header().Name
	apexname := strings.SplitAfter(name, DNSrhineCertPrefix)[1]

	var CaCertPool *x509.CertPool
	CaCertPool, _ = x509.SystemCertPool()

	CaCertPool.AppendCertsFromPEM(CaCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		DNSName: apexname,
		Roots:   CaCertPool,
	}); err != nil {
		fmt.Println("Rhine Cert Verification Failed!", err)
		return nil, nil, err
	}

	return cert, cert.PublicKey.(ed25519.PublicKey), nil
}

func extractROAFromMsg(msg *dns.Msg) (roa *ROA, domain string, ok bool) {
	var (
		rcert  *dns.TXT
		dnskey *dns.DNSKEY
		keySig *dns.RRSIG
		dSum   *dns.TXT
	)
	for _, r := range msg.Extra {
		switch r.Header().Rrtype {
		case dns.TypeDNSKEY:
			dnskey = r.(*dns.DNSKEY)
		case dns.TypeTXT:
			txt := r.(*dns.TXT)
			if IsRCert(txt) {
				rcert = txt
			} else if IsDSum(txt) {
				dSum = txt
			}
		case dns.TypeRRSIG:
			rrsig := r.(*dns.RRSIG)
			if rrsig.TypeCovered == dns.TypeDNSKEY {
				keySig = rrsig
			}
		}
	}
	if rcert == nil || dnskey == nil || keySig == nil {
		fmt.Printf("[RHINE] ;? Correct ROA not found in Msg\n")
		if rcert == nil {
			fmt.Printf("[RHINE] ;? RCert is null\n")
		}
		if dnskey == nil {
			fmt.Printf("[RHINE] ;? DNSKEY is null\n")
		}
		if keySig == nil {
			fmt.Printf("[RHINE] ;? keySig is null\n")
		}
		return nil, "", false
	}
	domain = strings.SplitAfter(rcert.Header().Name, DNSrhineCertPrefix)[1]
	fmt.Printf("[RHINE] ROA successfully extracted from response\n")
	return &ROA{keySig: keySig, rcert: rcert, dnskey: dnskey, dsum: dSum}, domain, true
}

func rhineRRSigCheck(in *dns.Msg, key *dns.DNSKEY) {
	if key == nil {
		fmt.Printf("[RHINE] DNSKEY not found for RRSIG checking\n")
		return
	}
	fmt.Printf("[RHINE] Start checking RRSIG in Answer section\n")
	rhineSectionCheck(in.Answer, key)
	fmt.Printf("[RHINE] Start checking RRSIG in Ns section\n")
	rhineSectionCheck(in.Ns, key)
}

func rhineSectionCheck(set []dns.RR, key *dns.DNSKEY) {
	for _, rr := range set {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			var expired string
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				expired = "(*EXPIRED*)"
			}
			rrset := getRRset(set, rr.Header().Name, rr.(*dns.RRSIG).TypeCovered)
			if err := rr.(*dns.RRSIG).Verify(key, rrset); err != nil {
				fmt.Printf("[RHINE] ;- Bogus signature, %s does not validate (DNSKEY %s/%d) [%s] %s\n",
					shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), err.Error(), expired)
			} else {
				fmt.Printf("[RHINE] ;+ Secure signature, %s validates (DNSKEY %s/%d) %s\n", shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), expired)
			}
		}
	}
}

func IsRCert(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSrhineCertPrefix)
}

func IsDSum(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSdsumprefix)
}

func IsRhineSig(txt *dns.TXT) bool {
	entries := txt.Txt
	entry := strings.Join(entries, " ")
	return strings.HasPrefix(entry, txtsigvalueprefix)
}
