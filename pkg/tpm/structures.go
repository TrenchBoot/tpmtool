package tpm

import (
	"github.com/rekby/gpt"
)

// [1] https://members.uefi.org/kws/documents/UEFI_Spec_2_7_A_Sept_6.pdf

// EFIGuid is the EFI Guid format
type EFIGuid struct {
	blockA uint32
	blockB uint16
	blockC uint16
	blockD uint16
	blockE [6]uint8
}

// EFIConfigurationTable is an internal UEFI structure see [1]
type EFIConfigurationTable struct {
	vendorGUID  EFIGuid
	vendorTable uint64
}

// EFIDevicePath is an internal UEFI structure see [1]
type EFIDevicePath struct {
	pathType    uint8
	pathSubType uint8
	length      [2]uint8
}

// TCGPCClientTaggedEvent is an legacy tag structure
type TCGPCClientTaggedEvent struct {
	taggedEventID       uint32
	taggedEventDataSize uint32
	taggedEventData     []byte
}

// EFIImageLoadEvent is an internal UEFI structure see [1]
type EFIImageLoadEvent struct {
	imageLocationInMemory uint64
	imageLengthInMemory   uint64
	imageLinkTimeAddress  uint64
	lengthOfDevicePath    uint64
	devicePath            []EFIDevicePath
}

// EFIGptData is the GPT structure
type EFIGptData struct {
	uefiPartitionHeader gpt.Header
	numberOfPartitions  uint64
	uefiPartitions      []gpt.Partition
}

// EFIHandoffTablePointers is an internal UEFI structure see [1]
type EFIHandoffTablePointers struct {
	numberOfTables uint64
	tableEntry     []EFIConfigurationTable
}

// EFIPlatformFirmwareBlob is an internal UEFI structure see [1]
type EFIPlatformFirmwareBlob struct {
	blobBase   uint64
	blobLength uint64
}

// EFIVariableData representing UEFI vars
type EFIVariableData struct {
	variableName       EFIGuid
	unicodeNameLength  uint64
	variableDataLength uint64
	unicodeName        []uint16
	variableData       []byte
}

// IHA is a TPM2 structure
type IHA struct {
	hash []byte
}

// THA is a TPM2 structure
type THA struct {
	hashAlg IAlgHash
	digest  IHA
}

// LDigestValues is a TPM2 structure
type LDigestValues struct {
	count   uint32
	digests []THA
}

// TcgEfiSpecIDEventAlgorithmSize is a TPM2 structure
type TcgEfiSpecIDEventAlgorithmSize struct {
	algorithID uint16
	digestSize uint16
}

// TcgEfiSpecIDEvent is a TPM2 structure
type TcgEfiSpecIDEvent struct {
	signature          [16]byte
	platformClass      uint32
	specVersionMinor   uint8
	specVersionMajor   uint8
	specErrata         uint8
	uintnSize          uint8
	numberOfAlgorithms uint32
	digestSizes        []TcgEfiSpecIDEventAlgorithmSize
	vendorInfoSize     uint8
	vendorInfo         []byte
}

// TcgBiosSpecIDEvent is a TPM2 structure
type TcgBiosSpecIDEvent struct {
	signature        [16]byte
	platformClass    uint32
	specVersionMinor uint8
	specVersionMajor uint8
	specErrata       uint8
	uintnSize        uint8
	vendorInfoSize   uint8
	vendorInfo       []byte
}

// TcgPcrEvent2 is a TPM2 default log structure (EFI only)
type TcgPcrEvent2 struct {
	pcrIndex  uint32
	eventType uint32
	digests   LDigestValues
	eventSize uint32
	event     []byte
}

// TcgPcrEvent is the TPM1.2 default log structure (BIOS, EFI compatible)
type TcgPcrEvent struct {
	pcrIndex  uint32
	eventType uint32
	digest    [20]byte
	eventSize uint32
	event     []byte
}

// PCRDigestValue is the hash and algorithm
type PCRDigestValue struct {
	DigestAlg IAlgHash
	Digest    []byte
}

// PCRDigestInfo is the info about the measurements
type PCRDigestInfo struct {
	PcrIndex     int
	PcrEventName string
	PcrEventData string
	Digests      []PCRDigestValue
}

// PCRLog is a generic PCR eventlog structure
type PCRLog struct {
	Firmware string
	PcrList  []PCRDigestInfo
}

// [2] http://kib.kiev.ua/x86docs/SDMs/315168-011.pdf (Pre-TrEE MLE Guide)
// [3] https://www.intel.com/content/dam/www/public/us/en/documents/guides/intel-txt-software-development-guide.pdf

// TxtEventLogContainer is log header for TPM1.2 TXT log
type TxtEventLogContainer struct {
	Signature         [20]uint8
	Reserved          [12]uint8
	ContainerVerMajor uint8
	ContainerVerMinor uint8
	PcrEventVerMajor  uint8
	PcrEventVerMinor  uint8
	Size              uint32
	PcrEventsOffset   uint32
	NextEventOffset   uint32
	//PcrEvents []byte
}

// TxtHeapEventLogDescr is TPM2 TXT log header before TrEE/UEFI format adoption
type TxtHeapEventLogDescr struct {
	Alg             uint16
	Reserved        uint16
	PhysAddr        uint64
	Size            uint32
	PcrEventsOffset uint32
	NextEventOffset uint32
}

// TxtHeapEventLogPtrElt2 is the Heap Element for TPM2 before TrEE/UEFI format adoption
type TxtHeapEventLogPtrElt2 struct {
	Count         uint32
	EventLogDescr []TxtHeapEventLogDescr
}

// TxtHeapEventLogPtrElt21 is the Heap Element for TPM2 conforming to TrEE/UEFI format
type TxtHeapEventLogPtrElt21 struct {
	PhysicalAddress             uint64
	AllocatedEventContainerSize uint32
	FirstRecordOffset           uint32
	NextRecordOffset            uint32
}
