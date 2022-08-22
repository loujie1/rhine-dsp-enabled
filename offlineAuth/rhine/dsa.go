package rhine

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/google/certificate-transparency-go/x509"
	"log"
	"time"
	//"github.com/rhine-team/RHINE-Prototype/offlineAuth/merkletree"
	"github.com/fxamacker/cbor/v2"
)

// Delegation Status Accumulator
type DSA struct {
	Zone     string
	Alv      AuthorityLevel
	Exp      time.Time
	Cert     []byte
	Acc      *MerkleTree
	Subzones []DSLeafContent

	Signature []byte
}

type DAcc struct {
	Zone     string
	Roothash []byte
}

type DSum struct {
	Dacc DAcc
	Alv  AuthorityLevel
	Cert []byte // hash of TBSRc_zone
	Sig  RhineSig
	//Exp  time.Time
}

func (d *DSA) GetDAcc() DAcc {
	return DAcc{
		Zone:     d.Zone,
		Roothash: d.Acc.Root.Hash,
	}
}

func (d *DSA) GetDSum() DSum {
	return DSum{
		Dacc: d.GetDAcc(),
		Alv:  d.Alv,
		Cert: d.Cert,
		//Exp:  d.Exp,
	}
}
func NewDSum(rcert *x509.Certificate, priv ed25519.PrivateKey, origin string) *DSum {
	dacc := DAcc{Zone: origin, Roothash: []byte{0, 0, 0, 0}}
	dsum := &DSum{Dacc: dacc, Alv: 0, Cert: ExtractTbsRCAndHash(rcert, false)}
	dsum.Sign(priv)
	return dsum
}
func (dsum *DSum) Sign(priv ed25519.PrivateKey) error {
	data, err := dsum.GetDSumToBytes()
	if err != nil {
		return err
	}

	dsum.Sig = RhineSig{
		Data: data,
	}

	err = dsum.Sig.Sign(priv)
	if err != nil {
		return err
	}

	return nil
}

func (dsum *DSum) Verify(pub interface{}, rcertp *x509.Certificate) bool {

	// Serialize DSP
	data, err := dsum.GetDSumToBytes()
	if err != nil {
		log.Println("Failed converting DSum to bytes")
		return false
	}

	// Verify dsp signature
	newSig := RhineSig{
		Data:      data,
		Signature: dsum.Sig.Signature,
	}
	veri := newSig.Verify(pub)
	if !veri {
		log.Printf("The signature did not verify for the DSP: %+v", dsum)
		return false
	}

	// Check if certificate in DSP matches PCert
	if bytes.Compare(dsum.Cert, ExtractTbsRCAndHash(rcertp, false)) != 0 {
		log.Println("Cert in DSP does not match PCert")
		return false
	}

	return true
}

func (dsum *DSum) GetDSumToBytes() ([]byte, error) {
	hasher := sha256.New()

	hasher.Write([]byte(dsum.Dacc.Zone))
	hasher.Write(dsum.Dacc.Roothash)
	hasher.Write([]byte{byte(dsum.Alv)})
	hasher.Write(dsum.Cert)

	//// expiration time
	//if timeBinary, err := dsum.Exp.MarshalBinary(); err != nil {
	//	return nil, err
	//} else {
	//	hasher.Write(timeBinary)
	//}

	return hasher.Sum(nil), nil
}
func (dsum *DSum) SerializeToString() (string, error) {
	res, err := cbor.Marshal(dsum)
	encoded := base64.StdEncoding.EncodeToString(res)
	if err != nil {
		fmt.Println("Error: ", err)
		return encoded, err
	}

	return encoded, nil
}

func (dsum *DSum) DeserializeFromString(input string) error {
	decodedDSA, _ := base64.StdEncoding.DecodeString(input)
	err := cbor.Unmarshal(decodedDSA, dsum)
	if err != nil {
		fmt.Println("Error: ", err)
		return err
	}
	return nil
}

func (d *DSA) SerializeToString() (string, error) {
	res, err := cbor.Marshal(d)
	encoded := base64.StdEncoding.EncodeToString(res)
	if err != nil {
		fmt.Println("Error: ", err)
		return encoded, err
	}

	return encoded, nil
}

func (d *DSA) DeserializeFromString(input string) error {
	decodedDSA, _ := base64.StdEncoding.DecodeString(input)
	err := cbor.Unmarshal(decodedDSA, d)
	if err != nil {
		fmt.Println("Error: ", err)
		return err
	}
	return nil
}
