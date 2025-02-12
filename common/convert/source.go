package convert

type SourceFormat string

const (
	SourceFormatGEOIP SourceFormat = "geoip"
	SourceFormatMMDB  SourceFormat = "mmdb"
	SourceFormatSRS   SourceFormat = "srs"
	SourceFormatMRS   SourceFormat = "mrs"
	SourceFormatTXT   SourceFormat = "text"
)

func (f SourceFormat) Valid() bool {
	switch f {
	case SourceFormatGEOIP, SourceFormatMMDB, SourceFormatSRS, SourceFormatMRS, SourceFormatTXT:
		return true
	default:
		return false
	}
}

type TargetFormat string

const (
	TargetFormatNftSet TargetFormat = "set"
)

func (f TargetFormat) Valid() bool {
	switch f {
	case TargetFormatNftSet:
		return true
	default:
		return false
	}
}
