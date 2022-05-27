package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gopaltirupur/appviewx-signer/internal/signer/common"
)

var vault *Vault

const (
	KUBE_TOKEN_PATH  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	VAULT_LOGIN_PATH = "v1/auth/kubernetes/login"

	VAULT_SECRET_TYPE_KV   = "kv"
	VAULT_SECRET_TYPE_LDAP = "ldap"
)

type Vault struct {
	VaultPasswordType string `json:"vaultPasswordType"`
	VaultIsHTTPS      bool   `json:"vaultIsHTTPS"`
	VaultHost         string `json:"vaultHost"`
	VaultPort         int    `json:"vaultPort"`
	VaultToken        string `json:"vaultToken"`
	VaultSecretPath   string `json:"vaultSecretPath"`
	VaultRole         string `json:"vaultRole"`
	VaultLoginPath    string `json:"vaultLoginPath"`
}

type VaultKVDataResponse struct {
	Data struct {
		Data map[string]string `json:"data"`
	} `json:"data"`
}

type VaultLDAPDataResponse struct {
	Data map[string]interface{} `json:"data"`
}

type VaultLoginResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
}

func init() {
	vault = &Vault{}

	var isAppViewXCredentialsFromVaultBool bool
	isAppViewXCredentialsFromVault := os.Getenv("VAULT_ENV_IS_APPVIEWX_CREDENTIALS_FROM_VAULT")
	if isAppViewXCredentialsFromVault == "" {
		isAppViewXCredentialsFromVaultBool = false
	} else {
		appviewxIsHTTPS, err := strconv.ParseBool(os.Getenv("VAULT_ENV_IS_APPVIEWX_CREDENTIALS_FROM_VAULT"))
		if err != nil {
			isAppViewXCredentialsFromVaultBool = false
		}
		isAppViewXCredentialsFromVaultBool = appviewxIsHTTPS
	}

	if isAppViewXCredentialsFromVaultBool {
		isHTTPS := os.Getenv("VAULT_ENV_IS_HTTPS")
		if isHTTPS == "" {
			vault.VaultIsHTTPS = true
		} else {
			vaultIsHTTPS, err := strconv.ParseBool(os.Getenv("VAULT_ENV_IS_HTTPS"))
			if err != nil {
				log.Fatalf("Error in parsing VAULT_ENV_IS_HTTPS with value %s", isHTTPS)
			}
			vault.VaultIsHTTPS = vaultIsHTTPS
		}

		vault.VaultPasswordType = os.Getenv("VAULT_ENV_PASSWORD_TYPE")
		vault.VaultHost = os.Getenv("VAULT_ENV_HOST")

		vaultPort, err := strconv.Atoi(os.Getenv("VAULT_ENV_PORT"))
		if err != nil {
			log.Fatalf("Error in parsing VAULT_ENV_PORT with value %s", os.Getenv("VAULT_ENV_PORT"))
		}
		vault.VaultPort = vaultPort

		vault.VaultSecretPath = os.Getenv("VAULT_ENV_SECRET_PATH")
		vault.VaultRole = os.Getenv("VAULT_ENV_ROLE")
		vault.VaultLoginPath = os.Getenv("VAULT_ENV_LOGIN_PATH")
	}

}

func GetAppViewXUserNameAndPassword(ctx context.Context) (string, string, error) {

	log.Println("Started GetAppViewXUserNameAndPassword")

	headers := make(map[string]string)
	vaultToken, err := vault.getToken(ctx)
	if err != nil {
		log.Printf("Error in getting the valt Token : %v\n", err)
		return "", "", err
	}
	headers["X-Vault-Token"] = vaultToken

	log.Println("Getting AppViewX Username and Password from Vault using Vault Token")
	url, err := common.GenerateURL(ctx, vault.VaultIsHTTPS, vault.VaultHost, vault.VaultPort, "/", vault.VaultSecretPath, nil)
	if err != nil {
		log.Println("Error in getting the url GetAppViewXUserNameAndPassword")
		return "", "", err
	}

	responseContents, err := vault.MakeGetCallAndReturnResponse(ctx, url, headers)
	if err != nil {
		log.Println("Error in getting response for GetAppViewXUserNameAndPassword - MakeGetCallAndReturnResponse ", err)
		return "", "", err
	}
	return vault.getUserNameAndPasswordForKVOrLDAP(responseContents)
}

func (vault *Vault) getUserNameAndPasswordForKVOrLDAP(responseContents []byte) (string, string, error) {
	switch strings.ToLower(vault.VaultPasswordType) {
	case VAULT_SECRET_TYPE_KV:
		log.Println("Parsing VAULT_SECRET_TYPE_KV")

		vaultKVDataResponse := &VaultKVDataResponse{}

		err := json.Unmarshal(responseContents, vaultKVDataResponse)
		if err != nil {
			log.Println(fmt.Sprintf("Error in parsing the vaultKVDataResponse : %s", string(responseContents)))
			return "", "", err
		}

		userName, userNameOK := vaultKVDataResponse.Data.Data["username"]
		if !userNameOK || userName == "" {
			log.Println("No username found in the KV response ", string(responseContents))
			return "", "", errors.New("no username found in the kv response ")
		}

		password, passwordOK := vaultKVDataResponse.Data.Data["password"]
		if !passwordOK || password == "" {
			log.Println("No password found in the KV response ", string(responseContents))
			return "", "", errors.New("no password found in the kv response")
		}
		log.Printf("Got Username ( length : %d ) and Password ( length : %d )\n", len(userName), len(password))
		return userName, password, nil

	case VAULT_SECRET_TYPE_LDAP:
		log.Println("Parsing VAULT_SECRET_TYPE_LDAP")

		vaultLDAPDataResponse := &VaultLDAPDataResponse{}

		err := json.Unmarshal(responseContents, vaultLDAPDataResponse)
		if err != nil {
			log.Println(fmt.Sprintf("Error in parsing the vaultLDAPDataResponse : %s", string(responseContents)))
			return "", "", err
		}

		userName, userNameOK := vaultLDAPDataResponse.Data["username"]
		if !userNameOK || userName == "" {
			log.Println("No username found in the LDAP response")
			// TODO: - TO REMOVE the responseContents
			return "", "", errors.New("no username found in the ldap response " + string(responseContents))
		}

		password, passwordOK := vaultLDAPDataResponse.Data["password"]
		if !passwordOK || password == "" {
			log.Println("No password found in the LDAP response")
			return "", "", errors.New("no password found in the ldap response" + string(responseContents))
		}
		userNameString := fmt.Sprintf("%s", userName)
		passwordString := fmt.Sprintf("%s", password)
		log.Printf("Got Username ( length : %d ) and Password ( length : %d )\n", len(userNameString), len(passwordString))
		return userNameString, passwordString, nil
	}
	return "", "", fmt.Errorf("given vault secret type does not have a handler : %s", strings.ToLower(vault.VaultSecretPath))
}

func (vault *Vault) MakeGetCallAndReturnResponse(
	ctx context.Context,
	url string,
	additionalRequestHeaders map[string]string,
) (output []byte, err error) {

	log.Println("url : " + url)
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(err, "Error in creating Post request ")
		return nil, err
	}

	for key, value := range additionalRequestHeaders {
		request.Header.Set(key, value)
	}

	response, err := client.Do(request)
	if err != nil {
		log.Println(err, "Error in making http request : ")
		return nil, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil || len(body) <= 0 {
		log.Println(err, "Error in reading the response : ")
		return nil, err
	}
	output = body
	return
}

func (vault *Vault) MakePostCallAndReturnResponse(
	ctx context.Context,
	url string,
	additionalRequestHeaders map[string]string,
	payload interface{},
) (output []byte, err error) {

	log.Println("url : " + url)
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	payloadContents, err := json.Marshal(payload)
	if err != nil {
		log.Println("Error in Marshalling the payload : ", err)
		return nil, err
	}

	payloadReader := bytes.NewReader(payloadContents)

	request, err := http.NewRequest("POST", url, payloadReader)
	if err != nil {
		log.Println(err, "Error in creating Post request ")
		return nil, err
	}

	for key, value := range additionalRequestHeaders {
		request.Header.Set(key, value)
	}

	response, err := client.Do(request)
	if err != nil {
		log.Println(err, "Error in making http request : ")
		return nil, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil || len(body) <= 0 {
		log.Println(err, "Error in reading the response : ")
		return nil, err
	}

	output = body
	return
}

func (vault *Vault) getToken(ctx context.Context) (string, error) {
	log.Println("Running Get Token")
	log.Printf("Reading the file %s for jwt token\n", KUBE_TOKEN_PATH)
	kubeTokenContents, err := ioutil.ReadFile(KUBE_TOKEN_PATH)
	if err != nil {
		log.Printf("Error in reading the file : %s : %v\n", KUBE_TOKEN_PATH, err)
		return "", err
	}
	log.Printf("jwt Token read success : Length : %d\n", len(kubeTokenContents))

	kubeToken := string(kubeTokenContents)

	url, err := common.GenerateURL(ctx, vault.VaultIsHTTPS, vault.VaultHost, vault.VaultPort, "/", vault.VaultLoginPath, nil)
	if err != nil {
		log.Println("Error in getting the url getToken - Login ", err)
		return "", err
	}

	log.Printf("Getting Client Token using jwt Token from Vault\n")
	payload := map[string]interface{}{}
	payload["jwt"] = kubeToken
	payload["role"] = vault.VaultRole

	responseContents, err := vault.MakePostCallAndReturnResponse(ctx, url, nil, payload)
	if err != nil {
		log.Println("Error in getting response for getToken - MakePostCallAndReturnResponse ", err)
		return "", err
	}

	// //TODO: - TO REMOVE
	// log.Printf("************************* Log responseContents %s\n", string(responseContents))

	vaultLoginResponse := VaultLoginResponse{}
	err = json.Unmarshal(responseContents, &vaultLoginResponse)
	if err != nil {
		log.Printf("Error in Unmarshalling for getToken : %v\n : %s \n", err, string(responseContents))
		return "", err
	}
	log.Printf("Got Client Token from Vault : Length : %d\n", len(vaultLoginResponse.Auth.ClientToken))

	if len(vaultLoginResponse.Auth.ClientToken) <= 0 {
		log.Printf("No Client Token in the response : %s\n", string(responseContents))
	}

	return vaultLoginResponse.Auth.ClientToken, nil
}
