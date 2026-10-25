package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
)

const MaxEventPageSize = 500

var ErrInvalidEventCursor = errors.New("invalid event cursor")

type eventPageCursor struct {
	IngestedAt time.Time `json:"ingested_at"`
	EventID    string    `json:"event_id"`
}

func encodeEventCursor(event model.Event) string {
	timestamp := event.IngestedAt
	if timestamp.IsZero() {
		timestamp = event.Time
	}
	payload, _ := json.Marshal(eventPageCursor{IngestedAt: timestamp.UTC(), EventID: event.ID})
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeEventCursor(cursor string) (eventPageCursor, error) {
	if cursor == "" {
		return eventPageCursor{}, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return eventPageCursor{}, ErrInvalidEventCursor
	}
	var decoded eventPageCursor
	if err := json.Unmarshal(payload, &decoded); err != nil || decoded.IngestedAt.IsZero() || decoded.EventID == "" || len(decoded.EventID) > 128 {
		return eventPageCursor{}, ErrInvalidEventCursor
	}
	return decoded, nil
}
