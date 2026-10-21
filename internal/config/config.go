package config

import "errors"

// Config contains only operator-owned push provider settings.
type Config struct {
	APNsKeyFile        string
	APNsKeyID          string
	APNsTeamID         string
	APNsTopic          string
	APNsSandbox        bool
	FCMCredentialsFile string
	FCMProjectID       string
	FCMApplicationID   string
}

func (c Config) ValidatePush() error {
	fcmConfigured := 0
	for _, v := range []string{c.FCMCredentialsFile, c.FCMProjectID, c.FCMApplicationID} {
		if v != "" {
			fcmConfigured++
		}
	}
	if fcmConfigured != 0 && fcmConfigured != 3 {
		return errors.New("FCM_CREDENTIALS_FILE, FCM_PROJECT_ID and FCM_APPLICATION_ID must be set together")
	}
	configured := 0
	for _, v := range []string{c.APNsKeyFile, c.APNsKeyID, c.APNsTeamID, c.APNsTopic} {
		if v != "" {
			configured++
		}
	}
	if configured != 0 && configured != 4 {
		return errors.New("APNS_KEY_FILE, APNS_KEY_ID, APNS_TEAM_ID and APNS_TOPIC must be set together")
	}
	return nil
}
