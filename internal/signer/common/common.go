package common

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	APPVIEWX_ENV_IS_HTTPS                = "APPVIEWX_ENV_IS_HTTPS"
	APPVIEWX_ENV_HOST                    = "APPVIEWX_ENV_HOST"
	APPVIEWX_ENV_PORT                    = "APPVIEWX_ENV_PORT"
	APPVIEWX_ENV_USER_NAME               = "APPVIEWX_ENV_USER_NAME"
	APPVIEWX_ENV_PASSWORD                = "APPVIEWX_ENV_PASSWORD"
	APPVIEWX_ENV_CERTIFICATE_AUTHORITY   = "APPVIEWX_ENV_CERTIFICATE_AUTHORITY"
	APPVIEWX_ENV_CA_SETTING_NAME         = "APPVIEWX_ENV_CA_SETTING_NAME"
	APPVIEWX_ENV_NAME                    = "APPVIEWX_ENV_CA_NAME"
	APPVIEWX_ENV_VALIDITY_IN_DAYS        = "APPVIEWX_ENV_VALIDITY_IN_DAYS"
	APPVIEWX_ENV_CERTIFICATE_GROUP_NAME  = "APPVIEWX_ENV_CERTIFICATE_GROUP_NAME"
	APPVIEWX_ENV_CATEGORY                = "APPVIEWX_ENV_CATEGORY"
	APPVIEWX_ENV_VENDOR_SPECIFIC_DETAILS = "APPVIEWX_ENV_VENDOR_SPECIFIC_DETAILS"
)

//ServerOpts to capture the server flags and start the server
type ServerOpts struct {
	GrpcHostName     string
	GrpcPort         string
	Protocol         string
	AppViewXHostName string
	AppViewXPort     string
	AppViewXIsHTTPS  bool
	CAName           string
	CASettingName    string
}

func (serverOpts ServerOpts) String() string {
	outputMarshalled, _ := json.Marshal(serverOpts)
	return string(outputMarshalled)
}

func GenerateURL(ctx context.Context, isHTTPS bool, host string, port int, mainPath string, subPath string, queryParam map[string]string) (string, error) {
	buffer := bytes.Buffer{}
	if isHTTPS {
		buffer.WriteString("https://")
	} else {
		buffer.WriteString("http://")
	}

	if len(host) > 0 {
		buffer.WriteString(host)
	} else {
		return "", errors.New("Error in appviewxHost : " + host)
	}

	if port > 0 {
		buffer.WriteString((":" + fmt.Sprintf("%d", port)))
	} else {
		return "", errors.New("Error in appviewxPort : " + fmt.Sprintf("%d", port))
	}

	buffer.WriteString(mainPath)

	buffer.WriteString(subPath)

	isItFirstTime := true
	for key, value := range queryParam {
		if isItFirstTime {
			isItFirstTime = false
			buffer.WriteString("?")
		} else {
			buffer.WriteString("&")
		}
		buffer.WriteString((key + "=" + value))
	}
	return buffer.String(), nil
}
