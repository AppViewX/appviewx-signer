package certs

//Sample certificates
func getAppViewXRootCert() (output []byte) {
	output = []byte(`
-----BEGIN CERTIFICATE-----
MIID5DCCAsygAwIBAgIQWWdOrbzHaHdkFNfGOtm3VDANBgkqhkiG9w0BAQsFADBh
MRQwEgYDVQQDDAtBcHBWaWV3WCBDQTEVMBMGA1UECgwMQXBwVmlld1ggSW5jMRAw
DgYDVQQHDAdTZWF0dGxlMRMwEQYDVQQIDApXYXNoaW5ndG9uMQswCQYDVQQGEwJV
UzAeFw0yMDA2MDIwODM0MzVaFw00MDA1MjgwODM0MzVaMGExFDASBgNVBAMMC0Fw
cFZpZXdYIENBMRUwEwYDVQQKDAxBcHBWaWV3WCBJbmMxEDAOBgNVBAcMB1NlYXR0
bGUxEzARBgNVBAgMCldhc2hpbmd0b24xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5AhB7Y12KKA0r7BEn1l8wiU61XwGGo+PVEMG
V1zg19cxzAVq1WtQvGpv5xZ7Lk/GMSpQ/lx26QieHM1mvntwkdd00krWUPCCHaxc
kMsz0NHCxou5KdhkAcU+yu7w88GmhtsKtJv+Cx0oiG3ZkIDXqkS6IO803O0o3KKy
GKheXlYlI/Y9VJj/cJmDzyFwKUa+ZnWfKR0LvUVjjtr09eJLBviAUDwZKaA1ET0N
LO7/cjvaMTDStMIbHvOx0iDeQ0VofCve3+cmiLUTJZ4M+mGthD3wgpRua+A+oBC2
XRpWPsq1gtArMbVhkat4MxqEy5iX/FjjhszCe5k0IhtPfXKS1wIDAQABo4GXMIGU
MB0GA1UdDgQWBBT2YPWewmlttDU1ScPk9jFo2eCRYjAPBgNVHRMBAf8EBTADAQH/
MA4GA1UdDwEB/wQEAwIBBjBSBggrBgEFBQcBAQRGMEQwQgYIKwYBBQUHMAGGNmh0
dHA6Ly90ZXN0LmNvbS9jb250cm9sbGVyL2F2eG9jc3A/aXNzdWVyc2VyaWFsbnVt
YmVyPTANBgkqhkiG9w0BAQsFAAOCAQEAmTeAGEmIkgBiXuLyzAP/9Rd6oyKALHnv
RBufkUKEKrjwVpY7vUnGeNM7hYs7Dxi64cQYuj98++lIAW/STrNOQWJp43O5z4o5
e1hh04kZ8OMBcuN8j/JvpRCHUDH3EadZqd7wB1THEiBgywnJkJ8nyr4xDwTASKDj
UdlfP5Q2LUctNF2oJpR0BDHXLNdP3hl5bGPPRHIgcw7qTwfqMEgl0x8O+Tk4E4Rs
EGuPyagX1xrTZ2MvNuEbxwyEYzmvtP9x0YbentGf5EaZZo9tQo3bLrcNsNxftXCp
Z0D0XxmB6QWWCUf3zXR1PUZTrR2J8cXdsDUA0OTPpiy3Q5+6GUpdNA==
-----END CERTIFICATE-----`)
	return
}

func getAppViewXInterMediateCert() (output []byte) {
	output = []byte(`
-----BEGIN CERTIFICATE-----
MIIFJDCCBAygAwIBAgIRAJJXTkbUOnawwWzxjrgKmn0wDQYJKoZIhvcNAQELBQAw
YTEUMBIGA1UEAwwLQXBwVmlld1ggQ0ExFTATBgNVBAoMDEFwcFZpZXdYIEluYzEQ
MA4GA1UEBwwHU2VhdHRsZTETMBEGA1UECAwKV2FzaGluZ3RvbjELMAkGA1UEBhMC
VVMwHhcNMjAwNjAyMDgzNDM2WhcNMjUwNjAxMDgzNDM2WjBuMSEwHwYDVQQDDBhB
cHBWaWV3WCBJbnRlcm1lZGlhdGUgQ0ExFTATBgNVBAoMDEFwcFZpZXdYIEluYzEQ
MA4GA1UEBwwHU2VhdHRsZTETMBEGA1UECAwKV2FzaGluZ3RvbjELMAkGA1UEBhMC
VVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIKDXaVzkp1GdF4NzH
2uFkb0TftTWzN9RrlWzA8S9t5YZoVl5BArs+78gy18R2HzxhjUye6i4+OGfbYJLe
qQ/XUT9RL9cCfiN70HpJzO5d3uLYPq9nZg/X71zSmdCDLMa07rc7LVwpSg4i0ox3
Pd452Lz0hDI9J9Jf4Xo6Mr7+jyhz8w7YZpZ+vzGqw9aWSXPGTDGKJM6nOUFHT9Ce
Ys77rRWsNViOUJg7ySu/VQenPtVfwgAHbU2hMwBRXApJOWPZhY5rXMFY9U3FmXd3
7HZ1zCBrjEnAYQK1ZdYN2NS76qGo7SJ8sQMoxzoqZ4iqO4KwUReY0kniV041tg8X
e7UZAgMBAAGjggHIMIIBxDAdBgNVHQ4EFgQUlkFmd9w91B+ZfNHvUTyubUUPsp8w
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwgZoGA1UdIwSBkjCBj4AU
9mD1nsJpbbQ1NUnD5PYxaNngkWKhZaRjMGExFDASBgNVBAMMC0FwcFZpZXdYIENB
MRUwEwYDVQQKDAxBcHBWaWV3WCBJbmMxEDAOBgNVBAcMB1NlYXR0bGUxEzARBgNV
BAgMCldhc2hpbmd0b24xCzAJBgNVBAYTAlVTghBZZ06tvMdod2QU18Y62bdUMGoG
A1UdHwRjMGEwX6BdoFuGWWh0dHA6Ly90ZXN0LmNvbS9jb250cm9sbGVyL2F2eGNy
bD9jcmxGaWxlTmFtZT0xMTg4Mzc2OTM5OTQxMzIwNTExNDUyMDU1MTQ1NDU4NDYx
Mzg3MDguY3JsMHkGCCsGAQUFBwEBBG0wazBpBggrBgEFBQcwAYZdaHR0cDovL3Rl
c3QuY29tL2NvbnRyb2xsZXIvYXZ4b2NzcD9pc3N1ZXJzZXJpYWxudW1iZXI9MTE4
ODM3NjkzOTk0MTMyMDUxMTQ1MjA1NTE0NTQ1ODQ2MTM4NzA4MA0GCSqGSIb3DQEB
CwUAA4IBAQDHXuOE7/PusPrPpvCemlf/AYu54s9KargxkIfM3DR5A6OCNegqjLvY
J9k1EciVHEBetmypkejtBn8WhW8NhBRIkxpMZPLFAWDleYXWH6I0Md/dFQeC5Y4w
rQbSvZ/8APs9+i2TPTB5WCgBEiTznonZs1D/1r+MS01Haeray1J6bRbhmSb7nLmC
eDMVRxFz82zzd4Gxm2To5WCMMDWPh/jfqJFzcNUz8DwGs8sk54nPjChbNW0quom1
4LGVKpNSK2JISL3bMH+IFdnxJBuAZpkLNixk8P+N7PDZ77GqLOjKb2q+GoDw2MwB
EX9GzADDzKB0dD7MXTXuViMM99uYcwlJ
-----END CERTIFICATE-----`)
	return
}

func getAppViewXInterMediateKey() (output []byte) {
	output = []byte(``)
	return
}
