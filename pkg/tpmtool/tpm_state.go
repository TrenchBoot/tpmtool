package tpmtool

import (
	"github.com/systemboot/tpmtool/pkg/tpm"
)

type Pcr struct {
	// PCR index
	index uint8
	// Current Hash
	hash PCRDigestInfo
	// Event Log
	log tpm.PCRLog
}

type PcrBank struct {
	// algId
	pcrs [tpm.TPMMaxPCRListSize]Pcr
}

type TpmState struct {
}

//
func (p *Pcr) Calculate() (PCRDigestInfo, error) {
	info := PCRDigestInfo{}
	return info, nil
}

// PCRDigestValue is the hash and algorithm
type PCRDigestValue struct {
	DigestAlg tpm.IAlgHash
	Digest    []byte
}

// PCRDigestInfo is the info about the measurements
type PCRDigestInfo struct {
	PcrIndex     int
	PcrEventName string
	PcrEventData string
	Digests      []PCRDigestValue
}

func (p *Pcr) Verify() error {
	// calculated, err := p.Calculate()
	//if err != nil {
	//	return err
	//}
	return nil
	//for _, d := range p.hash.Digests {
	//	matched := false
	//	for _, c := range calculated.Digests {
	//	}
	// }
	return nil
}

func (p *Pcr) FindEvent(evType uint32, evData []byte) (*PCRDigestInfo, error) {
	return nil, nil
}

func (p *Pcr) ReplaceEvent(evType uint32, evData []byte, ev *PCRDigestInfo) error {
	return nil
}
