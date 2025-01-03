package structs

type TemplateData[T any] struct {
	IP     string
	Events []T
}

type PortscanEvent struct {
	SrcIP     string
	SrcPort   uint16
	DstIP     string
	DstPort   uint16
	Timestamp string
}

type NullEvent struct{}
