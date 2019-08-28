package dtls

// Application data messages are carried by the record layer and are
// fragmented, compressed, and encrypted based on the current connection
// state.  The messages are treated as transparent data to the record
// layer.
// https://tools.ietf.org/html/rfc5246#section-10
type applicationData struct {
	data []byte
}

func (a applicationData) contentType() contentType {
	return contentTypeApplicationData
}

func (a *applicationData) Marshal(fragmentLen int) ([][]byte, error) {
	raw := append([]byte{}, a.data...)
	return [][]byte{raw}, nil
}

func (a *applicationData) Unmarshal(data []byte) error {
	a.data = append([]byte{}, data...)
	return nil
}
