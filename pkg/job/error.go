package job

import "encoding/json"

type ErrorSummaryMap map[string]ErrorSummary

type ErrorSummary struct {
	OS                     string `json:"os,omitempty"`
	OrchestrationError     error  `json:"orchestrationError,omitempty"`
	MalwareScanError       error  `json:"malwareScanError,omitempty"`
	VulnScanError          error  `json:"vulnScanError,omitempty"`
	ContainerVulnScanError error  `json:"containerVulnScanError,omitempty"`
	ArtifactAPIError       error  `json:"artifactAPIError,omitempty"`
}

type errorAlias ErrorSummary

type errSummary struct {
	OrchestrationError     string `json:"orchestrationError"`
	MalwareScanError       string `json:"malwareScanError"`
	VulnScanError          string `json:"vulnScanError"`
	ContainerVulnScanError string `json:"containerVulnScanError"`
	ArtifactAPIError       string `json:"artifactAPIError"`
	*errorAlias
}

func (s ErrorSummary) MarshalJSON() ([]byte, error) {
	return json.Marshal(&errSummary{
		OrchestrationError:     errorToString(s.OrchestrationError),
		MalwareScanError:       errorToString(s.MalwareScanError),
		VulnScanError:          errorToString(s.VulnScanError),
		ContainerVulnScanError: errorToString(s.ContainerVulnScanError),
		ArtifactAPIError:       errorToString(s.ArtifactAPIError),
		errorAlias:             (*errorAlias)(&s),
	})
}

func errorToString(err error) string {
	if err != nil {
		return err.Error()
	}
	return "null"
}
