package tpmtool

// CalculateType defines the calculation action for the PCR
type CalculateType string

const (
	// Static is hash of type byte array
	Static CalculateType = "static"
	// Dynamic is the current lookup of the PCR value
	Dynamic CalculateType = "dynamic"
	// Extend a hash into a PCR
	Extend CalculateType = "extend"
	// Measure a file into a PCR
	Measure CalculateType = "measure"
	// FirmwareLog is the TCPA ACPI log
	FirmwareLog CalculateType = "log"
	// Firmware which is platform specific
	Firmware CalculateType = "firmware"
	// Bootloader is the payload of the firmware
	Bootloader CalculateType = "bootloader"
	// Luks header of a block device
	Luks CalculateType = "luks"
	// Exclude a PCR from calculation
	Exclude CalculateType = "exclude"
)

// BootloaderType can be any bootloader
type BootloaderType int

const (
	// Systemboot is a LinuxBoot application
	Systemboot BootloaderType = 0
	// Grub2 is the Grand Unified Bootloader
	Grub2 BootloaderType = 1
	// SeaBios is an implementation of a legacy BIOS
	SeaBios BootloaderType = 2
)

// Luks1HeaderLength is the LUKS1 header length
const Luks1HeaderLength = 2048
