package aiagent

type Detection struct {
	Type     string `json:"Type"`
	Value    string `json:"Value"`
	Version  string `json:"Version,omitempty"`
	PURL     string `json:"PURL,omitempty"`
	FilePath string `json:"FilePath,omitempty"`
}

type AgentResult struct {
	AgentID       string      `json:"AgentID"`
	Name          string      `json:"Name"`
	Description   string      `json:"Description"`
	HomepageURL   string      `json:"HomepageURL"`
	RepositoryURL string      `json:"RepositoryURL"`
	PublishedAt   string      `json:"PublishedAt"`
	Version       string      `json:"Version"`
	Language      string      `json:"Language"`
	License       string      `json:"License"`
	Category      string      `json:"Category"`
	Platform      string      `json:"Platform"`
	Detections    []Detection `json:"Detections"`
}

func (r AgentResult) DataType() string {
	return "AIAGENT"
}

type ScanResult struct {
	Platform string        `json:"platform"`
	Agents   []AgentResult `json:"agents"`
}

func (r ScanResult) DataType() string {
	return "AIAGENT"
}
