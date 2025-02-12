package convert

type SourceFormat string

const (
	SourceFormatGEOIP SourceFormat = "geoip"
	SourceFormatMMDB  SourceFormat = "mmdb"
	SourceFormatSRS   SourceFormat = "srs"
	SourceFormatMRS   SourceFormat = "mrs"
	SourceFormatTXT   SourceFormat = "txt"
)

func (s SourceFormat) Valid() bool {
	switch s {
	case SourceFormatGEOIP, SourceFormatMMDB, SourceFormatSRS, SourceFormatMRS, SourceFormatTXT:
		return true
	default:
		return false
	}
}
