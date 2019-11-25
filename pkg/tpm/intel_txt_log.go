package tpm

import (
	"encoding/binary"
	"io"
	"log"
	"os"
)

func (e Txt12EvtType) String() string {
	switch e {
	case Txt12EvTypeBase:
		return "EVTYPE_BASE"
	case Txt12EvTypePcrMapping:
		return "EVTYPE_PCRMAPPING"
	case Txt12EvTypeHashStart:
		return "EVTYPE_HASH_START"
	case Txt12EvTypeMleHash:
		return "EVTYPE_MLE_HASH"
	case Txt12EvTypeBiosAcRegDaTa:
		return "EVTYPE_BIOSAC_REG_DA_TA"
	case Txt12EvTypeCpuScrtmStat:
		return "EVTYPE_CPU_SCRTM_STAT"
	case Txt12EvTypeLcpControlHash:
		return "EVTYPE_LCP_CONTROL_HASH"
	case Txt12EvTypeElementsHash:
		return "EVTYPE_ELEMENTS_HASH"
	case Txt12EvTypeStmHash:
		return "EVTYPE_STM_HASH"
	case Txt12EvTypeOsSinitDataCapHash:
		return "EVTYPE_OSSINITDATA_CAP_HASH"
	case Txt12EvTypeSinitPubKeyHash:
		return "EVTYPE_SINIT_PUBKEY_HASH"
	case Txt12EvTypeLcpHash:
		return "EVTYPE_LCP_HASH"
	}
	return ""
}

func (e Txt20EvtType) String() string {
	switch e {
	case Txt20EvTypeBase:
		return "EVTYPE_BASE"
	case Txt20EvTypePcrMapping:
		return "EVTYPE_PCRMAPPING"
	case Txt20EvTypeHashStart:
		return "EVTYPE_HASH_START"
	case Txt20EvTypeCombinedHash:
		return "EVTYPE_COMBINED_HASH"
	case Txt20EvTypeMleHash:
		return "EVTYPE_MLE_HASH"
	case Txt20EvTypeBiosAcRegData:
		return "EVTYPE_BIOSAC_REG_DATA"
	case Txt20EvTypeCpuScrtmStat:
		return "EVTYPE_CPU_SCRTM_STAT"
	case Txt20EvTypeLcpControlHash:
		return "EVTYPE_LCP_CONTROL_HASH"
	case Txt20EvTypeElementsHash:
		return "EVTYPE_ELEMENTS_HASH"
	case Txt20EvTypeStmHash:
		return "EVTYPE_STM_HASH"
	case Txt20EvTypeOsSinitDataCapHash:
		return "EVTYPE_OSSINITDATA_CAP_HASH"
	case Txt20EvTypeSinitPubKeyHash:
		return "EVTYPE_SINIT_PUBKEY_HASH"
	case Txt20EvTypeLcpHash:
		return "EVTYPE_LCP_HASH"
	case Txt20EvTypeLcpDetailsHash:
		return "EVTYPE_LCP_DETAILS_HASH"
	case Txt20EvTypeLcpAuthoritiesHash:
		return "EVTYPE_LCP_AUTHORITIES_HASH"
	case Txt20EvTypeNvInfoHash:
		return "EVTYPE_NV_INFO_HASH"
	case Txt20EvTypeColdBootBiosHash:
		return "EVTYPE_COLD_BOOT_BIOS_HASH"
	case Txt20EvTypeKmHash:
		return "EVTYPE_KM_HASH"
	case Txt20EvTypeBpmHash:
		return "EVTYPE_BPM_HASH"
	case Txt20EvTypeKmInfoHash:
		return "EVTYPE_KM_INFO_HASH"
	case Txt20EvTypeBpmInfoHash:
		return "EVTYPE_BPM_INFO_HASH"
	case Txt20EvTypeBootPolHash:
		return "EVTYPE_BOOT_POL_HASH"
	case Txt20EvTypeCapValue:
		return "EVTYPE_CAP_VALUE"
	}
	return ""
}

func readTxt12Log(path string) (*PCRLog, error) {
	var pcrLog PCRLog
	var container TxtEventLogContainer

	file, err := os.Open(path)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer file.Close()

	for {
		// TxtEventLogContainer
		if err := binary.Read(file, binary.LittleEndian, &container.Signature); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		// skip reserve
		file.Seek(12, 1)

		if err := binary.Read(file, binary.LittleEndian, &container.ContainerVerMajor); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, binary.LittleEndian, &container.ContainerVerMinor); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, binary.LittleEndian, &container.PcrEventVerMajor); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, binary.LittleEndian, &container.PcrEventVerMinor); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, binary.LittleEndian, &container.Size); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, binary.LittleEndian, &container.PcrEventsOffset); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, binary.LittleEndian, &container.NextEventOffset); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		// seek to first PCR event
		file.Seek(int64(container.PcrEventsOffset), 0)

		var pcrDigest PCRDigestInfo
		var pcrEvent TcgPcrEvent

		if err := binary.Read(file, binary.LittleEndian, &pcrEvent.pcrIndex); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, binary.LittleEndian, &pcrEvent.eventType); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, binary.LittleEndian, &pcrEvent.digest); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, binary.LittleEndian, &pcrEvent.eventSize); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		pcrEvent.event = make([]byte, pcrEvent.eventSize)
		if err := binary.Read(file, binary.LittleEndian, &pcrEvent.event); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		pcrDigest.Digests[0].Digest = make([]byte, TPMAlgShaSize)
		copy(pcrDigest.Digests[0].Digest, pcrEvent.digest[:])

		if BIOSLogTypes[BIOSLogID(pcrEvent.eventType)] != "" {
			pcrDigest.PcrEventName = BIOSLogTypes[BIOSLogID(pcrEvent.eventType)]
		}
		if EFILogTypes[EFILogID(pcrEvent.eventType)] != "" {
			pcrDigest.PcrEventName = EFILogTypes[EFILogID(pcrEvent.eventType)]
		}

		eventDataString, _ := getEventDataString(pcrEvent.eventType, pcrEvent.event)
		if eventDataString != nil {
			pcrDigest.PcrEventData = *eventDataString
		}

		pcrDigest.PcrIndex = int(pcrEvent.pcrIndex)
		pcrLog.PcrList = append(pcrLog.PcrList, pcrDigest)
	}

	return &pcrLog, nil
}
